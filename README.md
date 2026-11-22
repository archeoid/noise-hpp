# noise-hpp

A tiny header-only C++11 [Noise Protocol (revision 34)](https://noiseprotocol.org/noise.html) implementation using OpenSSL.

### Requirements
- C++11 or higher
- OpenSSL 3.0+

### Usage
```cpp
#include "noise.hpp"
#include <iostream>

int main() {
    NoiseHandshake client("Noise_NN_25519_ChaChaPoly_SHA256", true);
    NoiseHandshake server("Noise_NN_25519_ChaChaPoly_SHA256", false);
    uint8_t message[128]{}, plaintext[128]{};
    size_t used = 0, received = 0;

    // Handshake
    client.write(nullptr, 0, message, sizeof(message), used);
    server.read(message, used, plaintext, sizeof(plaintext), received);
    server.write(nullptr, 0, message, sizeof(message), used);
    client.read(message, used, plaintext, sizeof(plaintext), received);

    // Transport
    auto client_transport = client.split();
    auto server_transport = server.split();
    const char text[] = "hello";
    uint64_t nonce = 0;

    client_transport.encrypt(nonce, (const uint8_t*)text, sizeof(text) - 1, message, sizeof(message), used);
    server_transport.decrypt(nonce, message, used, plaintext, sizeof(plaintext), received);
    std::cout.write((const char*)plaintext, received);
    std::cout << '\n';
}
```
```
g++ -std=c++11 example.cpp -lcrypto -o example
./example
```

### Notes
- Optional nonce protection modes are provided beyond the Noise specification, with a 64-message replay window enabled by default.
- Half-duplex mode can result in catastrophic nonce reuse if both peers transmit simultaneously. Your application protocol must define the initial sender and enforce strict alternation between sending and receiving.
- Consult the [Noise Protocol (revision 34)](https://noiseprotocol.org/noise.html) specification for details.
