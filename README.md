#  STX-DataShield -  A Privacy Data Access Control Smart Contract

## Overview

This smart contract implements a privacy-focused data access control system on the Stacks blockchain using the Clarity language. It allows users to register, manage their encrypted profile data, and control access permissions for other users requesting access to their data. The contract enforces permission levels and expiry periods to ensure secure and granular control over sensitive information.

---

## Features

* **User Registration:** Users can register themselves with optional encrypted data.
* **Data Management:** Registered users can update their encrypted data hash securely.
* **Access Control:** Users can grant and revoke data access permissions to other users with defined permission levels and time limits.
* **Permission Levels:** Access permissions are categorized into levels (e.g., Basic Profile, Personal Details, Financial Records, Medical History).
* **Access Verification:** Requesters can verify if they currently have access to a user's data.
* **Admin Controls:** Contract administrator can modify user permission levels within configured bounds.
* **Privacy Data Categories:** Predefined categories of data with associated minimum permission levels.

---

## Error Codes

| Code                             | Description                                             |
| -------------------------------- | ------------------------------------------------------- |
| `ERROR-UNAUTHORIZED-ACCESS`      | Caller lacks required permissions.                      |
| `ERROR-USER-ALREADY-EXISTS`      | User is already registered.                             |
| `ERROR-USER-NOT-FOUND`           | User does not exist in registry.                        |
| `ERROR-INVALID-PERMISSION-LEVEL` | Provided permission level is invalid or exceeds limits. |
| `ERROR-ACCESS-PERIOD-EXPIRED`    | Access permission has expired.                          |
| `ERROR-INVALID-INPUT`            | Input parameters are invalid (e.g., buffer length).     |

---

## Data Structures

### Registered Users Map

Stores user information keyed by principal address:

* `is-active` (bool): Whether the user is currently active.
* `encrypted-data-hash` (optional (buff 32)): Encrypted hash of user data.
* `profile-update-timestamp` (uint): Block height of last update.
* `user-permission-level` (uint): User’s assigned permission level.

### User Access Registry

Tracks access granted from one user to another:

* `access-granted` (bool): Whether access is currently granted.
* `access-expiry-height` (uint): Block height when access expires.
* `granted-permission-level` (uint): Permission level granted.

### Privacy Data Categories

Defines categories of data and their minimum required permission levels:

| Category ID | Category Name         | Minimum Permission Level |
| ----------- | --------------------- | ------------------------ |
| 1           | Basic-Profile         | 1                        |
| 2           | Personal-Details      | 2                        |
| 3           | Sensitive-Information | 3                        |
| 4           | Financial-Records     | 4                        |
| 5           | Medical-History       | 5                        |

---

## Contract Variables

* `contract-administrator` (principal): The admin with special privileges.
* `minimum-required-permission` (uint): Minimum user permission level allowed (default: 1).
* `maximum-allowed-permission` (uint): Maximum user permission level allowed (default: 5).

---

## Public Functions

### `register-new-user(initial-data-hash (optional (buff 32)))`

Register a new user with optional encrypted data hash.

* Fails if the user already exists or input buffer length is invalid.
* Sets initial permission level to minimum required permission.

### `update-encrypted-data(updated-data-hash (buff 32))`

Update the user’s encrypted data hash.

* Requires user to be registered.
* Validates the length of the buffer.

### `grant-data-access(requesting-party principal, access-permission-level uint, access-duration uint)`

Grant another user permission to access data.

* Access level cannot exceed the grantor's permission level.
* Duration defines how many blocks access is valid for.

### `revoke-data-access(access-requester principal)`

Revoke access previously granted to a requester.

### `request-user-data-access(target-data-owner principal)`

Request access to another user's data.

* Succeeds only if valid, unexpired access permission exists.

### `modify-user-permission-level(target-user principal, new-permission-level uint)`

Admin-only function to modify a user’s permission level.

* Permission level must be within allowed bounds.

---

## Read-Only Functions

### `get-user-profile-data(target-user principal)`

Returns stored user profile data.

### `verify-data-access(data-owner principal, data-requester principal)`

Returns true if the requester currently has access permission.

### `get-detailed-access-permissions(data-owner principal, data-requester principal)`

Returns detailed access permission information for a requester.

---

## Initialization

On contract deployment, the following privacy data categories are set up:

* Basic-Profile (Level 1)
* Personal-Details (Level 2)
* Sensitive-Information (Level 3)
* Financial-Records (Level 4)
* Medical-History (Level 5)

---

## Usage Notes

* Access permissions expire after the block height defined when granting access.
* Users can only grant access permissions up to their own permission level.
* Only the contract administrator can modify user permission levels.
* Encrypted data is stored as a 32-byte buffer hash for privacy and integrity.

---

## Security Considerations

* Ensure the contract administrator role is securely controlled.
* Validate all inputs thoroughly (buffer sizes, permission levels).
* Revoke access promptly when needed to maintain data privacy.

---

## License

Specify your preferred open-source license here.

