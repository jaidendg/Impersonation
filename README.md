# Windows Token Impersonation

This is a small C project that demonstrates Windows token impersonation using the Windows API.

In this example, the program targets `lsass.exe`, a Windows process responsible for authentication and security. Because of its role in credential management, LSASS is frequently targeted during credential-access attacks.

**This program must be run as Administrator in order to access LSASS**

---

## What this does

* enables `SeDebugPrivilege` for the current process
* finds the PID of `lsass.exe` using `CreateToolhelp32Snapshot`
* retrieves the access token of the target process using `OpenProcessToken`
* duplicates the token using `DuplicateTokenEx`
* impersonates the duplicated token on the current thread using `SetThreadToken`
* reverts impersonation using `RevertToSelf`
* closes all opened handles

---

## Build

```bash
gcc src/main.c -o bin/main
```

```bash
./bin/main
```
