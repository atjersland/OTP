# One-Time Pad

## Description
A One-Time Pad tool incorporating HMAC and keyed plaintext shuffle.

## Table of contents
1. [Key Features](#key-features)
    1. [Hash-Based Message Authentication Code (HMAC)](#hash-based-message-authentication-code-(hmac))
    2. [Fisher-Yates Shuffle](#fisher-yates-shuffle)
2. [Usage Examples](#usage-examples)
    1. [Create Padbook](#create-padbook)
    2. [Encrypt Message](#encrypt-message)
	3. [Decrypt Message](#decrypt-message)
	4. [Notes](#notes)
3. [Warnings](#warnings)
4. [File Structures](#file-structure)

## Key Features

### Hash-Based Message Authentication Code (HMAC)
HMAC is a mitigation for the inherent malleability of OTP messages. This implementation uses a quantity of bytes from the pad data as a Nonce for an HMACSHA512 MAC.

This feature makes it simple for the recipient to verify the integrity of the cyphertext and plaintext contents.

### Fisher-Yates Shuffle
The Fisher-Yates keyed shuffle method is an improved approach to the Russian Copulation technique for countering known text attacks. This algorithm shuffles elements in an array based on a provided key and allows for the un-shuffling of the array given the original key.

This increases the difficulty for adversaries that are attempting a brute force decryption. Even known or expected words in the message will be shuffled into an ambiguous mixture.

## Usage Examples

### Create Padbook
`./oneTimePad -g -b example.bin -o padDir`

* -g: Use a bin file to generate a directory of pad files.
* -b: Path for the bin file for generating pad files.
* -o: Path for the output files.

### Encrypt Message
`./oneTimePad -e -m message.txt -p pad1.xml -o message.xml`

* -e: Encrypt a plaintext message using the specified pad file.
* -m: Path for the plaintext or encrypted message file.
* -p: Path to the pad file.
* -o: Path for the output files.

### Decrypt Message
`./oneTimePad -d -m message.xml -p pad1.xml -o message.txt`

* -d: Decrypt an encrypted message using the specified pad file.
* -m: Path for the plaintext or encrypted message file.
* -p: Path to the pad file.
* -o: Path for the output files.

### Notes

* Maximum Message Length: The message must be equal to or shorter than the key.
* Padding: If the message is shorter than the key this tool appends psudo-random chars to the end of the message. This is the only place a psudo-random function is used.

## Warnings
Ensuring the secure deletion of files within this application poses a challenge without a universally dependable solution. Users should use operating system and storage-specific methods for securely deleting files.

For the generation of pad data, it's crucial to derive it from a true random bit source. Pseudo-random number generators are not sufficient for this purpose due to their deterministic nature.

For a robust solution, I recommend exploring my [RNG-RD](https://github.com/atjersland/RNG-RD) project, which focuses on providing a reliable source of true random bits.

## File Structures
```
message.xml
<message>
    <mac></mac>
    <body></body>
</message>
```

```
padx.xml
<pad>
    <nonceBytes></nonceBytes>
    <shuffleBytes></shuffleBytes>
    <messageBytes></messageBytes>
</pad>
```