# Networks & System Security

**SIL765 & COL7165 - Assignment 2**
**Deadline:** February 22, 2026

## Instructions

- This assignment is a capture-the-flag problem.
- You will be given one VirtualBox image of an Ubuntu Linux system.
- There are five problem sets.
- For each problem, you need to create a file in the stated format only.
- A helper function has been written to create the text files in the correct format. You can use it to create the tarball for submission.
- The VirtualBox 'appliance' is available at <https://owncloud.iitd.ac.in/nextcloud/index.php/s/ZiZZEpyK3dp7nC7>
- Problems with the assignment should be raised as issues on the GitHub repository <https://github.com/boardslayer/CTF-SIL765>

## Problem 1: Gain Access

You are a penetration tester tasked with checking the security of a deployment server. You have been made aware that not all users are following the security guidelines given to them. Try and find a way inside the system.

**Goal:** Obtain an unprivileged shell. Extract the flag stored inside the home folder.
**Hint:** Think of ways that information may leak on a public server. How does one connect to the server to work?

**Solution Format**
Submit a single tarball named `[EntryNumber]-P1.tar.gz`, e.g., `2022CSZ228227-P1.tar.gz`. The file should contain `flag.txt` and `key.txt`.

```text
[EntryNumber]-P1.tar.gz
|-- flag.txt
`-- key.txt
```

## Problem 2: Become Super

In your home folder you have three programs that you can execute. They are called `vuln1`, `vuln2`, and `vuln3`. You can run them, but you cannot modify them. Can you use them to gain root access?

**Goal:** Obtain a privileged (root) shell and extract the flag stored inside the root user's home directory. Once done you can use the helper function to create the text.

**Hint:** You are provided with several executable programs inside the vulnerable user's home directory. Can they be used somehow?

**Solution Format**
Submit a single tarball named `[EntryNumber]-P2.tar.gz`, e.g., `2022CSZ228228-P2.tar.gz`. The file should contain `flag.txt` and `key.txt`.

```text
[EntryNumber]-P2.tar.gz
|-- flag.txt
`-- key.txt
```

## Problem 3: Changing the Flow

In this problem, you are provided with a standalone program that processes user input and makes internal decisions based on it. While the program appears to function normally, subtle implementation flaws may allow an attacker to redirect its execution.

**Goal:** Manipulate the program's execution flow to execute a target function already in the binary to obtain the protected flag.

**Hint:** How do you _win_ a game of memory? Where do you write things temporarily when you run a program? Carefully analyze how the program stores and returns control during execution.

**Solution Format**
Submit a single tarball named `[EntryNumber]-P3.tar.gz`, e.g., `2022CSZ228229-P3.tar.gz`. The file should contain `flag.txt` and `key.txt`.

```text
[EntryNumber]-P3.tar.gz
|-- flag.txt
`-- key.txt
```

## Problem 4: Is 'In and Out' Safe?

In the previous problem, you redirected execution by corrupting control data. Is there another way of redirecting execution without modifying control data?

**Goal:** Exploit some input vulnerability to obtain a protected flag.

**Hint:** Output functions may interpret user input in unexpected ways. Consider how formatted output functions process arguments internally.

**Solution Format**
Submit a single tarball named `[EntryNumber]-P4.tar.gz`, e.g., `2022CSZ228230-P4.tar.gz`. The file should contain `flag.txt` and `key.txt`.

```text
[EntryNumber]-P4.tar.gz
|-- flag.txt
`-- key.txt
```

## Problem 5: CSS Hijacking

In this problem, you are given a local web application running at <http://localhost:5005>. Gain access to the admin page and find the hidden flag. The user account you have access to is `ctfadmin` with password same as the username.

**Goal:** Use CSS hijacking to reveal the `ctfadmin` flag.

**Hint:** The admin page loads a user‑supplied stylesheet. Look for ways CSS can change visibility or style of hidden elements.
**Access:** Connect via VNC (host port `5901`) and open Epiphany (`epiphany-browser`) in the VM.

**Solution Format**
Submit a single tarball named `[EntryNumber]-P5.tar.gz`, e.g., `2022CSZ228231-P5.tar.gz`. The file should contain `flag.txt` and `key.txt`.

```text
[EntryNumber]-P5.tar.gz
|-- flag.txt
`-- key.txt
```
