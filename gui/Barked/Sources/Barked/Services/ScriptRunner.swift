import Foundation
import Combine
import AppKit

@MainActor
class ScriptRunner: ObservableObject {
    @Published var output: String = ""
    @Published var isRunning: Bool = false
    @Published var exitCode: Int32?

    private var process: Process?
    private var outputPipe: Pipe?

    /// Path to barked.sh — prefers system install, falls back to bundled
    var scriptPath: String {
        for path in ["/usr/local/bin/barked", "\(FileManager.default.homeDirectoryForCurrentUser.path)/.local/bin/barked"] {
            if FileManager.default.isExecutableFile(atPath: path) { return path }
        }
        return Bundle.main.path(forResource: "barked", ofType: "sh")
            ?? "/usr/local/bin/barked"
    }

    /// Path to Bash 4+ — prefers Homebrew, falls back to system
    var bashPath: String {
        for path in ["/opt/homebrew/bin/bash", "/usr/local/bin/bash"] {
            if FileManager.default.isExecutableFile(atPath: path) { return path }
        }
        return "/bin/bash"
    }

    /// Run barked.sh with arguments, streaming stdout/stderr
    func run(_ arguments: [String]) async {
        output = ""
        isRunning = true
        exitCode = nil

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: bashPath)
        proc.arguments = [scriptPath] + arguments

        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = pipe
        proc.standardInput = FileHandle.nullDevice

        self.process = proc
        self.outputPipe = pipe

        // Stream output
        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty, let str = String(data: data, encoding: .utf8) else { return }
            Task { @MainActor [weak self] in
                self?.output += str
            }
        }

        do {
            try proc.run()
            // Wait off the main thread to keep UI responsive
            await withCheckedContinuation { continuation in
                DispatchQueue.global().async {
                    proc.waitUntilExit()
                    continuation.resume()
                }
            }
        } catch {
            self.output += "\nError: \(error.localizedDescription)"
        }

        pipe.fileHandleForReading.readabilityHandler = nil
        isRunning = false
        exitCode = proc.terminationStatus
        self.process = nil
    }

    /// Run with administrator privileges (shows reason alert then system auth dialog)
    func runPrivileged(_ arguments: [String], reason: String) async -> (output: String, exitCode: Int32) {
        // Bring app to front and explain why root is needed
        NSApplication.shared.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "Administrator Access Required"
        alert.informativeText = reason
        alert.alertStyle = .informational
        alert.addButton(withTitle: "Continue")
        alert.addButton(withTitle: "Cancel")
        let response = alert.runModal()
        guard response == .alertFirstButtonReturn else {
            output = "Cancelled by user."
            exitCode = 1
            return (output, 1)
        }

        isRunning = true
        output = ""
        exitCode = nil

        let args = ([scriptPath] + arguments)
            .map { "'\($0.replacingOccurrences(of: "'", with: "'\\''"))'" }
            .joined(separator: " ")
        let script = "do shell script \"\(bashPath) \(args)\" with administrator privileges"

        var result = ""
        var code: Int32 = 0

        let appleScript = NSAppleScript(source: script)
        var errorDict: NSDictionary?
        if let scriptResult = appleScript?.executeAndReturnError(&errorDict) {
            result = scriptResult.stringValue ?? ""
        } else {
            let errMsg = errorDict?[NSAppleScript.errorMessage] as? String ?? "Unknown error"
            result = "Error: \(errMsg)"
            code = 1
        }

        output = result
        isRunning = false
        exitCode = code
        return (result, code)
    }

    /// Cancel a running process
    func cancel() {
        process?.terminate()
    }
}
