# decrypt-tokens [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

A Go library for decrypting tokens from virtual wallets (e.g., ApplePay, GooglePay).

## 📖 Overview

### What is this library?

This Go library provides tools to decrypt tokens from virtual wallet payment systems, currently focusing on ApplePay decryption with plans to expand to GooglePay.

### Motivation

This project was born from the challenges faced while implementing Apple Pay token decryption in a professional environment. Existing JOSE libraries were outdated and incompatible with Apple's strict NIST SP 800-56A standard requirements. This implementation aims to simplify the process for developers working with payment token decryption in Go.

## 🚀 Features

- ApplePay token signature verification (EC-based)
  - ApplePay token decryption 


## 📦 Installation

```bash 
go get github.com/megazordcarioca/decrypt-tokens
```
For detailed module-specific documentation, see:

* <b>Apple Pay Module Guide

* <b>Google Pay Module (Coming Soon)

## 📝 TODO List

  - ApplePay
    - [ ] Add RSA decryption support for Apple Pay
    - [ ] Optimize certificate verification redundancy
    - [ ] Refactor Apple Pay module
  - Google Pay
    - [ ] Implement Google Pay module


## 🤝 Contributing

* We welcome contributions! Please feel free to:

* Open issues for feature requests/bugs

* Fork the repository

* Submit PRs with improvements

* Share the project with others

## ⚖️ License
This project is licensed under GNU GPLv3 - see LICENSE for details.

## 📬 Contact
Email: josiasdsj1@gmail.com

LinkedIn: https://linkedin.com/in/megamd