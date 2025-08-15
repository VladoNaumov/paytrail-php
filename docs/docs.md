php -S 127.0.0.1:8888 


curl.exe -i -X POST "https://www.encanta.fi/demo/index.php?action=callback&__debug=headers" -H "Signature: test" -H "checkout-account: 375917" -H "checkout-algorithm: sha256" -H "checkout-method: POST" -H "checkout-timestamp: 2025-08-15T21:20:08Z" -H "checkout-nonce: abc123" --data "{}"
