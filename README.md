# ETW Patch Tool

**A tool for patching ETW (Event Tracing for Windows) functions such as `EtwEventWrite` and `EtwEventWriteFull`.**

This tool demonstrates how to patch the `EtwEventWrite` and `EtwEventWriteFull` functions to disable event tracing in a target process by modifying the `call` instruction to prevent tracing events from being logged.

## Features:
- **Patch ETW Functions**: The tool patches either the `EtwEventWrite` or `EtwEventWriteFull` function by locating the `call` instruction in memory and replacing it with NOP (`0x90`) instructions, effectively neutralizing the function call.
- **Memory Permissions Handling**: The tool changes the memory permissions of the ETW function before patching to ensure that the process memory can be written to.
- **Custom Patch with XOR/RET**: Additionally, the tool provides the option to replace the `EtwEventWriteFull` function with a simple `xor eax, eax` and `ret` instruction, effectively disabling the function.

## Usage:
```bash
ETWPatch.exe <PID>


![image](https://github.com/zer0antisec/RemoteEtwPatch/assets/20486087/e362e236-becf-4588-9dc4-c1995e91857f)
