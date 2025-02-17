---
title: Protocol Audit Report
author: David Korgalidze
date: February 11, 2025
header-includes:
  - \usepackage{titling}
  - \usepackage{graphicx}
---

# Password Storing Smart Contract Audit Report

Prepared by: DAVID KORGALIDZE

- DAVID KORGALIDZE [linkedin](https://www.linkedin.com/in/dato-korgalidze/)

Assisting Auditors:

- None

# Table of Contents

- [Password Storing Smart Contract Audit Report](#password-storing-smart-contract-audit-report)
- [Table of Contents](#table-of-contents)
- [Protocol Summary](#protocol-summary)
- [Disclaimer](#disclaimer)
- [Risk Classification](#risk-classification)
- [Audit Details](#audit-details)
  - [Scope](#scope)
  - [Roles](#roles)
- [Executive Summary](#executive-summary)
  - [Issues found](#issues-found)
- [Findings](#findings)
  - [High](#high)
    - [\[H-1\] Storing the password on-chain makes it visable to anyone,and it is not private.](#h-1-storing-the-password-on-chain-makes-it-visable-to-anyoneand-it-is-not-private)
  - [Likelihood and Impact:](#likelihood-and-impact)
    - [\[H-2\] `PasswordStore::setPassword` has no access controls, meaning a non-owner could change the password](#h-2-passwordstoresetpassword-has-no-access-controls-meaning-a-non-owner-could-change-the-password)
  - [Likelihood and Impact:](#likelihood-and-impact-1)
  - [Informational](#informational)
    - [\[I-1\] The `PasswordStore::getPassword` natspec indicates a parameter that doesn't exist, causing the natspec to be incorrect.](#i-1-the-passwordstoregetpassword-natspec-indicates-a-parameter-that-doesnt-exist-causing-the-natspec-to-be-incorrect)
  - [Likelihood and Impact:](#likelihood-and-impact-2)

# Protocol Summary

PasswordStore is a protocol dedicated to storage and retrieval of a user's passwords. The protocol is designed to be used by a single user, and is not designed to be used by multiple users. Only the owner should be able to set and access this password.

# Disclaimer

This audit report is provided for informational purposes only. It is not a guarantee of security or functionality. The findings and recommendations are based on the current state of the code and may not cover all potential risks. Use this report at your own discretion, and ensure thorough testing and review before deploying any smart contract. The auditors are not liable for any damages or losses resulting from the use of this report or the audited code.

# Risk Classification

|            |        | Impact |        |     |
| ---------- | ------ | ------ | ------ | --- |
|            |        | High   | Medium | Low |
|            | High   | H      | H/M    | M   |
| Likelihood | Medium | H/M    | M      | M/L |
|            | Low    | M      | M/L    | L   |

We use the [CodeHawks](https://docs.codehawks.com/hawks-auditors/how-to-evaluate-a-finding-severity) severity matrix to determine severity. See the documentation for more details.

# Audit Details

**The findings described in this document correspond the following commit hash:**

```bash
   2e8f81e263b3a9d18fab4fb5c46805ffc10a9990

```

## Scope

```
  src/
#-- PasswordStore.sol

```

## Roles

- Owner: Is the only one who should be able to set and access the password.
- For this contract, only the owner should be able to interact with the contract.

# Executive Summary

**This audit assessed the security of the PasswordStore smart contract. Three issues were identified:**

- High Severity: Password stored on-chain, making it publicly visible.
- High Severity: No access control on the setPassword function, allowing unauthorized password changes.
- Informational: Incorrect natspec documentation in the getPassword function.

The recommended mitigations include implementing access controls, securing password storage off-chain, and fixing documentation inconsistencies.

## Issues found

| Severity | Number of issues found |
| -------- | ---------------------- |
| High     | 2                      |
| Medium   | 0                      |
| Low      |                        |
| Info     | 1                      |
| Total    | 3                      |

# Findings

## High

### [H-1] Storing the password on-chain makes it visable to anyone,and it is not private.

**Description:** All data stored on chain is public and visible to anyone. The `PasswordStore::s_password` variable is intended to be hidden and only accessible by the owner through the `PasswordStore::getPassword` function.

**Impact:** Anyone is able to read the private password, severely breaking the functionality of the protocol.

**Proof of Concept:**
the below test case shows how anyone could read the password from the bolockchain.

1. Create a locally running chain

```bash
   make anvil
```

2. Deploy the contract to the chain.

```bash
  make deploy
```

3.  Run the storage tool

We use 1 because that's the storage slot of s_password in the contract.

```bash
cast storage <ADDRESS_HERE> 1 --rpc-url http://127.0.0.1:8545
```

4. You'll get an output that looks like this:

```bash
0x6d7950617373776f726400000000000000000000000000000000000000000014
```

5. You can then parse that hex to a string with:

```bash
cast parse-bytes32-string 0x6d7950617373776f726400000000000000000000000000000000000000000014
```

6. And get an output of:

```bash
myPassword
```

**Recommended Mitigation:**

**Secure Off-Chain Storage:**

Avoid storing sensitive information, such as passwords, directly on-chain since all blockchain data is publicly accessible. Instead, store passwords securely off-chain using encrypted storage solutions (e.g., secure backends, encrypted databases, or secure key management systems).

**On-Chain Reference to Encrypted Data:**

If referencing the password is necessary on-chain, store only the cryptographic hash of the password (using SHA-256 or Keccak256) instead of the plaintext value. This approach allows verification without revealing the actual password.

**Example Implementation:**

Modify the contract to store the password hash and verify the user's input:

```javascript
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

contract PasswordStore {
    address private s_owner;
    bytes32 private s_passwordHash;

    event PasswordUpdated(bytes32 passwordHash);

    constructor() {
        s_owner = msg.sender;
    }

    function setPassword(string memory newPassword) external onlyOwner {
        s_passwordHash = keccak256(abi.encodePacked(newPassword));
        emit PasswordUpdated(s_passwordHash);
    }

    function verifyPassword(string memory password) external view onlyOwner returns (bool) {
        return keccak256(abi.encodePacked(password)) == s_passwordHash;
   }

}
```

## Likelihood and Impact:

- Impact: High
- LikeliHood: High
- Severity: High

### [H-2] `PasswordStore::setPassword` has no access controls, meaning a non-owner could change the password

**Description:** The `PasswordStore::setPassword` function is set to be an `external` function, however the purpose of the smart contract and function's natspec indicate that `This function allows only the owner to set a new password.`

```javascript
function setPassword(string memory newPassword) external {
    // @Audit - There are no Access Controls.
    s_password = newPassword;
    emit SetNewPassword();
}
```

**Impact:** Anyone can set/change the stored password.

**Proof of Concept:**
Add the following to the PasswordStore.t.sol test suite.

```javascript
 function test_anyone_can_set_password(address randomAddress) public {
        vm.assume(randomAddress != owner);
        vm.prank(randomAddress);
        string memory randomAddressPassword = "newPassword";
        passwordStore.setPassword(randomAddressPassword);

        vm.prank(owner);
        string memory owenrsPassword = "newPassword";
        passwordStore.setPassword(owenrsPassword);
        assertEq(randomAddressPassword, owenrsPassword);
    }
```

**Recommended Mitigation:**
Add an access control modifier to the `setPassword` function.

```javascript
   if (msg.sender != s_owner) {
   revert PasswordStore__NotOwner();
}
```

## Likelihood and Impact:

- Impact: High
- LikeliHood: High
- Severity: High

## Informational

### [I-1] The `PasswordStore::getPassword` natspec indicates a parameter that doesn't exist, causing the natspec to be incorrect.

**Description:**

```javascript
/*
 * @notice This allows only the owner to retrieve the password.
@> * @param newPassword The new password to set.
 */
function getPassword() external view returns (string memory) {}
```

The `PasswordStore::getPassword` function signature is `getPassword()` while the natspec says it should be `getPassword(string)`.

**Impact** The natspec is incorrect

**Recommended Mitigation:** Remove the incorrect natspec line

```diff
- * @param newPassword The new password to set.
```

## Likelihood and Impact:

- Impact: None
- LikeliHood: High
- Severity: Informational/Gas/Non-crit

Informational: This is not a bug,but you should know (fix)..,
