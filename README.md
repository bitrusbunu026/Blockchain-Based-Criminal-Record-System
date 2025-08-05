# 🏛️ Blockchain-Based Criminal Record System

A secure and transparent criminal record management system built on the Stacks blockchain using Clarity smart contracts. This system enables authorized users like courts to create, seal, and disclose criminal records with proper verification and consent mechanisms.

## ✨ Features

- 🔐 **Role-based Access Control**: Different permission levels for admins, courts, law enforcement, and viewers
- 📋 **Record Management**: Create, seal, and disclose criminal records with full audit trails
- ✅ **Consent Management**: Handle subject consent for record access and disclosure
- 🔍 **Audit Logging**: Complete access logs for transparency and accountability
- 🛡️ **Data Integrity**: Blockchain-based verification of record authenticity
- 🚫 **Privacy Protection**: Sealed records require court-level authorization

## 🎭 User Roles

| Role | Level | Permissions |
|------|-------|-------------|
| Admin | 1 | Full system control, user management |
| Court | 2 | Create, seal, disclose records |
| Law Enforcement | 3 | View active records |
| Viewer | 4 | Basic record viewing |

## 📊 Record Status Types

- **Active** (1): Normal accessible records
- **Sealed** (2): Restricted access, court authorization required
- **Disclosed** (3): Previously sealed, now accessible with consent

## 🚀 Getting Started

### Prerequisites

- [Clarinet](https://github.com/hirosystems/clarinet) installed
- Stacks wallet for testing

### Installation

1. Clone the repository
```bash
git clone <repository-url>
cd blockchain-criminal-record-system
