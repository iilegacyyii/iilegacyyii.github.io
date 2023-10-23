---
layout: post
title: Writing a Windows Fuzzer From Scratch
date: 2023-10-23 17:00:00 +0100
categories: VR Windows
---

Over the past year, I have dedicated a large majority of my spare time to studying Windows internals. Doing so got me hooked on content from vulnerability research space, and such I have started learning how to fuzz simple windows targets. 

Whilst I'm comfortable using tools such as [What the fuzz](https://github.com/0vercl0k/wtf), I figured it'd be useful to write my own fuzzer in order to gain a proper understanding of how things work under the hood. This post documents my initial design, alongside some potential optimisations, and will hopefully give a foundation for those who are looking to get started.

**Quick disclaimer**: This is by no means optimal, and the hardcore devs will sob, however it's designed to be easy to understand for someone new to the topic and I personally think it accomplishes that.

# Contents
1. [What Is Fuzzing, and Why Is It Useful?](#what-is-fuzzing-and-why-is-it-useful)
2. [Fuzzer Overview](#fuzzer-overview)
3. [The Target](#the-target)
4. [Writing The Fuzzer](#writing-the-fuzzer)
	- [Mutator](#mutator)
		- [Constructor & Destructor](#constructor--destructor)
		- [Get Set & Reset MutatedInput](#get-set--reset-mutatedinput)
		- [Mutation Methods](#mutation-methods)
	- [Execution Engine](#execution-engine)
		- [Constructor & Destructor](#constructor--destructor-1)
		- [RunTestCase](#runtestcase)
	- [Bringing It All Together](#bringing-it-all-together)
5. [Benchmarking](#benchmarking)
	- [Test 1 - No Crashes](#test-1---no-crashes)
	- [Test 2 - Crashes](#test-2---crashes)
6. [Conclusion](#conclusion)
7. [References](#references)

# What Is Fuzzing, and Why Is It Useful?

Whilst I usually don't like to quote Wikipedia, they have a very good summary of fuzzing:  

*"In programming and software development, fuzzing or fuzz testing is an automated software testing technique that involves providing invalid, unexpected, or random data as inputs to a computer program. The program is then monitored for exceptions such as crashes, failing built-in code assertions, or potential memory leaks."* ~ [wikipedia.org/wiki/fuzzing](https://en.wikipedia.org/wiki/Fuzzing)  

Fuzzing is almost quintessential for those looking to find new memory corruption bugs without spending a painstaking amount of time reverse engineering the target. This comes in especially handy when looking at functionality such as deserialisation, file format parsing, or packet parsers.

# Fuzzer Overview

The fuzzer is comprised of two core parts, a "mutator" and an "execution engine". 

The mutator takes a given user input and mutates it, usually in ways of which are likely to trigger bugs (e.g. extending length/flipping bits). On the other hand, the execution engine takes the mutated input, and passes this to the target, executing our test case. It then checks if a crash is detected, and if so will notify the user so that they can further analyse this and look to develop an exploit.

# The Target

For sake of the initial POC, I created as simple of a test target as I could think of - a `strcpy` based stack overflow. In future posts I will look to showcase a more complex target, but for now this is enough for a POC.

**main.cpp**
```cpp
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <Windows.h>


int main(int argc, char** argv, char** envp)
{
	char name[64] = { 0 };

	if (argc != 2)
	{
		puts("Usage: .\\FuzzMe <name>");
		return 0;
	}

	strcpy(name, argv[1]); // unsafe

	printf("Hello: %s\n", name);
	return 0;
}
```

# Writing The Fuzzer

I chose to write the Fuzzer in C++, whilst others have decided to show an initial POC in python, such as in [h0mbre](https://twitter.com/h0mbre_)'s [Fuzzing Like A Caveman](https://h0mbre.github.io/Fuzzing-Like-A-Caveman/) (a huge inspiration for this series), I personally prefer to jump straight into the C++ side of things for both speed, and lack of fighting the python abstraction layer. 

As mentioned previously, this fuzzer will be comprised of two main components, the mutator, and the execution engine itself. There will also be some code to execute our main fuzzing loop, but that will be quite short.

_Note: `logging.h` is just a modified version of `debug.h` from my [UsefulScripts GitHub repo](https://github.com/iilegacyyii/UsefulScripts#debugh)._

## Mutator

The mutator will be in charge of modifying our initial input, creating malformed payloads to be passed to our target. Therefore it requires a few essential pieces of functionality, once those are implemented, it can be extended in any variety of ways:

- `SetInput`
	- Sets the fuzzer's base input to later be mutated.
- `ResetMutatedInput`
	- Resets the fuzzer's mutated input back to the original input, ready to be mutated again.
- `GetMutatedInput`
	- Retrieves the mutated input after our chosen mutation methods have been applied.

As for how the mutator will mutate user input, I chose to add two methods to this fuzzer, `ExtendInput` and `FlipBits`:

- `ExtendInput`
	- Extends the length of the current input by a random amount of bytes, padding empty space with null bytes.
- `FlipBits`
	- Randomly flips bits in the current input. Without this, we would simply be extending input length with null bytes, and that wouldn't trigger our bug.

By the end of this section, the following `Mutator` class will be fully implemented:

**mutator.hpp**

```cpp
#pragma once
#include <Windows.h>
#include <random>

class Mutator 
{
	BYTE* _Input;
	SIZE_T _InputLength;
	BYTE* _MutatedInput;
	SIZE_T _MutatedInputLength;
public:
	Mutator();
	~Mutator();
	BOOL ExtendInput(SIZE_T Amount = NULL);
	VOID FlipBits();
	BYTE* GetMutatedInput();
	BOOL ResetMutatedInput();
	BOOL SetInput(BYTE* Bytes, SIZE_T Length);
};
```

### Constructor & Destructor

First, I implemented the constructor and destructor methods of our class, these will handle initialisation of our private fields (`_Input`, `_InputLength`, etc.) and freeing the allocated heap chunks during cleanup respectively.

**mutator.cpp**

```cpp
Mutator::Mutator() // constructor
{
	srand(time(0)); // seed prng
	this->_Input = (BYTE*)malloc(0);
	this->_InputLength = 0;
	this->_MutatedInput = (BYTE*)malloc(0);
	this->_MutatedInputLength = 0;
}

Mutator::~Mutator() // destructor
{
	free(this->_Input);
	free(this->_MutatedInput);
}
```

### Get Set & Reset MutatedInput

Next, I implemented `GetMutatedInput`, `SetMutatedInput`, and `ResetMutatedInput`. As these are fairly self explanatory, I will just include the source below.

```cpp
BYTE* Mutator::GetMutatedInput()
{
	return this->_MutatedInput;
}

BOOL Mutator::ResetMutatedInput()
{
	// Cleanup mutated input
	free(this->_MutatedInput);
	
	// Create a copy of this->_Input and allocate as _MutatedInput
	this->_MutatedInput = (BYTE*)malloc(this->_InputLength);
	this->_MutatedInputLength = this->_InputLength;
	if (this->_MutatedInput == FALSE) return FALSE;

	memcpy(this->_MutatedInput, this->_Input, this->_MutatedInputLength);
	return TRUE;
}

BOOL Mutator::SetInput(BYTE* Bytes, SIZE_T Length)
{
	// Allocate new original input
	BYTE* NewInput = (BYTE*)realloc(this->_Input, Length);
	if (NewInput == NULL) return FALSE;

	// Again, for the input to be mutated
	BYTE* NewMutatedInput = (BYTE*)realloc(this->_MutatedInput, Length);
	if (NewMutatedInput == NULL)
	{
		// No need to free this->_Input, is done in destructor
		return FALSE;
	}

	// If successful, replace inputs with our new heap chunks 
	// (using realloc so no need to free the originals)
	this->_Input = NewInput;
	this->_InputLength = Length;
	this->_MutatedInput = NewMutatedInput;
	this->_MutatedInputLength = Length;

	memcpy(this->_Input, Bytes, Length);
	memcpy(this->_MutatedInput, Bytes, Length);
	return TRUE;
}
```

### Mutation Methods

Now that getting, setting, and resetting of inputs is implemented. It is time to start work on the fun part, mutation methods.

**ExtendInput**

This method will extend `_MutatedInput` by `Amount` bytes. `Amount` can either be pre-defined or will be a randomly selected value between 1 and 4096. The extra `Amount` bytes will be set to null bytes.

```cpp
BOOL Mutator::ExtendInput(SIZE_T Amount)
{
	if (!Amount)
	{
		// If no amount specified, expand string by up to 4096 bytes
		Amount = rand() % 4096;
		if (Amount == 0) Amount++; // Will extend by 1 at minimum
	}

	// Attempt to extend MutatedInput to the new size
	BYTE* NewMutatedInput = (BYTE*)malloc(this->_MutatedInputLength + Amount);
	if (!NewMutatedInput) return FALSE;

	// Fill with null bytes and write current MutatedInput to the start
	memset(NewMutatedInput, 0, this->_MutatedInputLength + Amount);
	memcpy(NewMutatedInput, this->_MutatedInput, this->_MutatedInputLength);

	// Replace mutated input fields
	free(this->_MutatedInput);
	this->_MutatedInput = NewMutatedInput;
	this->_MutatedInputLength = this->_MutatedInputLength + Amount;

	return TRUE;
}
```

**FlipBits**

As the name suggests, `FlipBits` will randomly flip bits in `_MutatedInput`. There are a variety of ways to approach this, for example only flipping bits in X percent of bytes. However, to keep things easy to understand, I decided to just flip bits in every byte of `_MutatedInput`. 

```cpp
VOID Mutator::FlipBits()
{
	for (SIZE_T i = 0; i < this->_MutatedInputLength; i++)
	{
		this->_MutatedInput[i] ^= rand() % 256; // randomly flip bits given values from 0-255
	}
}
```

Now that `Mutator` is fully implemented, I looked to create the `ExecutionEngine`.

## Execution Engine

As shown in the [target source](#the-target) above, our target will take user input from `argv[1]`, and so we shall look to build the execution engine (in this case also acting as our harness). In order to keep this as simple as possible, `ExecutionEngine` will have just one key method `RunTestCase`.

Similar to the `Mutator` class, by the end of this section the following class will be fully implemented:

```cpp
#pragma once
#include <Windows.h>
#include <random>
#include "logging.hpp"

class ExecutionEngine
{
	BYTE* _ExecutablePath;
public:
	ExecutionEngine(BYTE* ExecutablePath);
	~ExecutionEngine();
	DWORD RunTestCase(BYTE* Input);
};
```

### Constructor & Destructor

In the case of such a basic execution engine, one could argue that these aren't really necessary. However, I personally consider it good practice to have both for every class. The source is as follows:

```cpp
ExecutionEngine::ExecutionEngine(BYTE* ExecutablePath)
{
	this->_ExecutablePath = ExecutablePath;
}

ExecutionEngine::~ExecutionEngine()
{
	
}
```

### RunTestCase

This is the meat of the `ExecutionEngine` class. In order to keep this explanation brief, I have summarised it below in bullet points:

1. Initialise variables needed for call to `CreateProcessA`
2. Create an instance of the specified target using `_ExecutablePath`
3. Wait until the process exits
4. Store the exit code
5. Cleanup handles

The commented source is as follows:

```cpp
DWORD ExecutionEngine::RunTestCase(BYTE* Input)
{
	DWORD exit_code = 0;
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES | CREATE_NO_WINDOW; // dont inherit stdin/stderr/stdout

	// spawn target process with Input being passed into arguments
	if (!CreateProcessA((LPCSTR)this->_ExecutablePath,(LPSTR)Input,
		NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
	{
		LOG_ERROR("Failed to create process (0x%08lx)", GetLastError());
		return -1;
	}

	// Wait for process to exit, and store the exit code
	WaitForSingleObject(pi.hProcess, INFINITE);
	GetExitCodeProcess(pi.hProcess, &exit_code);
	
	// cleanup handles
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	return exit_code;
}
```

With `ExecutionEngine` fully implemented, we just need to bring it all together to create a fuzzing loop.

## Bringing it All Together

Now that the core functionality for the fuzzer was implemented, I wrapped it in the following control flow:

1. Ensure proper args have been passed (`Usage: .\FirstFuzzer.exe <exe> <initial_input>`)
2. Check target exe exists and that the user read/execute permissions
3. Set `Mutator`'s initial input, and `ExecutionEngine`'s target exe 
4. Run the fuzzer loop for `1000` iterations
	- Mutate input with `ExtendInput` and `FlipBits` methods
	- Execute the target via `RunTestCase`, providing our mutated input
	- Log crash if there is one
	- Reset mutated input
5. Print fuzzing stats
6. Cleanup

The commented source for this has been given below: 

```cpp
#include <windows.h>
#include <iostream>
#include <time.h>
#include "logging.hpp"
#include "mutator.hpp"
#include "executionEngine.hpp"

int main(int argc, char** argv, char** envp)
{
	int return_val = 0;
	SIZE_T iteration_goal = 300;
	Mutator* mutator = NULL;
	ExecutionEngine* execution_engine = NULL;
	DWORD exit_code = NULL;
	clock_t begin, end;
	double time_spent;
	
	// Make sure there's 3 args
	if (argc < 3)
	{
		LOG_ERROR("Invalid usage");
		printf("    Usage: .\\FirstFuzzer.exe <exe> <initial_input>\n");
		return -1;
	}

	// Check target exe exists
	HANDLE file_handle = CreateFileA(
		argv[1], 
		GENERIC_READ | GENERIC_EXECUTE, 
		NULL, NULL, 
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (file_handle == INVALID_HANDLE_VALUE)
	{
		LOG_ERROR("File '%s' either does not exist, or you do not have permissions to execute", argv[1]);
		return_val = -1;
		goto CLEANUP;
	}
	CloseHandle(file_handle);
	LOG_SUCCESS("Target exe '%s'", argv[1]);

	// Set initial input
	mutator = new Mutator();
	if (mutator->SetInput((BYTE*)argv[2], strlen(argv[2])) == FALSE)
	{
		LOG_ERROR("Insufficient memory to allocate initial input");
		return_val = -1;
		goto CLEANUP;
	}

	// Start fuzzing
	begin = clock();
	execution_engine = new ExecutionEngine((BYTE*)argv[1]);
	for (SIZE_T iteration_count = 0; iteration_count < iteration_goal; iteration_count++)
	{
		// mutate inputs
		mutator->ExtendInput();
		mutator->FlipBits();

		// Run test case and check output
		exit_code = execution_engine->RunTestCase(mutator->GetMutatedInput());
		if (exit_code != 0)
		{
			LOG_SUCCESS("Process exited with code: %d", exit_code);
		}

		// Reset ready for the next test case
		mutator->ResetMutatedInput();

		// Handle display
		if (iteration_count % 100 == 0)
		{
			printf("%lld/%lld iterations\r", iteration_count, iteration_goal);
		}
	}

	// Final stats output
	end = clock();
	time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	LOG_SUCCESS("%lld executions in %fs (%f/s)", iteration_goal, time_spent, iteration_goal/time_spent);

	CLEANUP:
	delete mutator;
	delete execution_engine;

	return return_val;
}
```

# Benchmarking

So in order to acquire a fair benchmark, I decided to perform two tests: 

1. Run for 100, 1000, and 10000 iterations against target executable with just `ExtendedInput` mutation rule (should have no crashes)
2. Same as before, except with the `FlipBits` mutation rule added (will have many crashes)

Performing both of these allows for a measure of the performance defecit of having the target executable crash rather than exiting cleanly.

## Test 1 - No Crashes

| Iterations | Total time taken (s) | Iterations/s |
| ---------- | -------------------- | ------------ |
| 100        | 0.347s               | 288.184438   |
| 1000       | 3.308s               | 302.297461   |
| 10000      | 35.210               | 284.010224   |

This gives an average of `285.604` iterations/s over the course of `11100` iterations, in the case of which there are no crashes.

## Test 2 - Crashes

| Iterations | Total time taken (s) | Iterations/s |
| ---------- | -------------------- | ------------ |
| 100        | 3.419                | 29.248318    |
| 1000       | 36.228               | 27.602959    |
| 10000      | 328.949              | 30.399849    |

This gives an average of `30.114` iterations/s over the course of `11100` iterations, in the case of which there are no crashes. As you can see, this is approximately `9.5` times slower than fuzzing without crashes, and shows a good worst case in terms of performance defecit.

# Conclusion

After having set out to create a simple fuzzer, I had managed exactly that, and with speeds that are honestly not terrible given how un-optimised it is. In the next post, I will look to reduce the performance deficit incurred from a crash, implement proper crash logs, and perhaps point this at a real-world target!

Massive thanks to those in the vulnerability research community for publishing their tooling, as well as providing writeups of their shenanigans, as without them I wouldn't have been able to learn about such an interesting topic.

# References

- [Fuzzing Like A Caveman](https://h0mbre.github.io/Fuzzing-Like-A-Caveman/) - Awesome series by [h0mbre](https://twitter.com/h0mbre_), inspiring this series
- [Competing in Pwn2Own ICS 2022 Miami: Exploiting a zero click remote memory corruption in ICONICS Genesis64](https://doar-e.github.io/blog/2023/05/05/competing-in-pwn2own-ics-2022-miami-exploiting-a-zero-click-remote-memory-corruption-in-iconics-genesis64/) - An awesome Pwn2Own journey writeup by [0vercl0k](https://twitter.com/0vercl0k)
