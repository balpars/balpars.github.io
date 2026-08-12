---
title: "Computing Without Decrypting: An Introduction to Homomorphic Encryption"
author: balpars
published: 2026-08-12
draft: false
tags:
  - cryptography
description: "What can we design so that even a breached server does not have everything the attacker wants?"
toc: true
series: 'Cryptography Basics'
---

	# Computing on Data You Cannot Read

## Motivation

We are pretty good at encrypting data.

When data is stored on disk, we can encrypt it.

When data travels across a network, we can protect it with TLS.

The problem starts when we actually want to **use** that data.

Consider a server processing sensitive customer information.

At rest:

```text
Database
   ↓
Encrypted
```

In transit:

```text
Client ─── TLS ─── Server
```

But eventually the application has to do something with the information.

Maybe calculate a credit score.

Maybe analyze medical measurements.

Maybe calculate statistics over salaries.

Traditionally, that means:

```text
Encrypted Data
      ↓
   Decrypt
      ↓
  Plaintext
      ↓
  Calculate
      ↓
   Encrypt
```

And that creates an interesting security problem.

The attacker does not necessarily need to break AES.

They do not necessarily need to defeat TLS either.

If the server itself is compromised, they may simply wait until the application decrypts the data.

The encryption did its job while the information was stored and transmitted.

But the application eventually needed the plaintext.

So what if we simply removed that requirement?

What if the server could calculate something **without ever learning what it was calculating on?**

Instead of:

```text
Encrypted Data
      ↓
   Decrypt
      ↓
  Plaintext
      ↓
 Compute
```

we could have:

```text
Encrypted Data
      ↓
 Compute
      ↓
Encrypted Result
```

No plaintext in the middle.

That is the idea behind **Homomorphic Encryption**.

---

## The Strange Idea

Imagine a company has the following salary data:

```text
50,000
72,000
91,000
```

The company wants to use a cloud analytics service.

But it does not want the cloud provider to know any employee salaries.

Normally those two requirements conflict.

The server needs the data in order to calculate something about the data.

Homomorphic Encryption changes that assumption.

The company first encrypts the values locally:

```text
50000  ──encrypt──>  ciphertext_1
72000  ──encrypt──>  ciphertext_2
91000  ──encrypt──>  ciphertext_3
```

The cloud receives only ciphertext.

It performs a calculation:

```text
ciphertext_1
      +
ciphertext_2
      +
ciphertext_3
```

and gets another ciphertext.

The result is returned to the company.

Only the company holds the secret key, so only the company can decrypt the answer.

Conceptually:

```text
CLIENT

[50000, 72000, 91000]
          |
          | Encrypt
          v

   Encrypted Salaries
          |
          |
          v

CLOUD SERVER

   Encrypted Salaries
          |
          | Compute
          v
    Encrypted Result
          |
          |
          v

CLIENT

    Encrypted Result
          |
          | Decrypt
          v

         71000
```

The cloud calculated an average salary without learning any individual salary.

That is already interesting.

From a security perspective, though, there is another consequence that interests me even more.

## What Happens During a Breach?

Suppose our analytics server is compromised.

With a traditional architecture, the attacker might obtain:

```text
Application memory
Database credentials
Temporary files
Application logs
Plaintext values currently being processed
```

Even if the database itself is encrypted, the application usually has access to the decryption key somewhere because it needs the plaintext to operate.

With a properly designed homomorphic system, the compute server does **not need the secret key at all**.

It receives ciphertext.

It computes on ciphertext.

It returns ciphertext.

The secret key remains somewhere else.

So compromising the compute environment can result in something quite different:

```text
Attacker compromises server
          |
          v

Encrypted input
Encrypted intermediate values
Encrypted output
Public/evaluation keys
```

rather than:

```text
Attacker compromises server
          |
          v

Plaintext customer dataset
```

This does not make breaches harmless.

Metadata can still leak.

Application logic can still have vulnerabilities.

The client holding the secret key can still be compromised.

Results themselves may reveal information.

And Homomorphic Encryption does not magically provide integrity against every malicious server.

But it can dramatically reduce one particularly dangerous assumption:

> The machine performing the computation does not necessarily need access to the underlying data.

This is sometimes described as protecting **data in use**.

---

## How Can You Calculate Something You Cannot Read?

Suppose:

```text
Enc(x)
```

means the encrypted representation of `x`.

A homomorphic encryption scheme allows certain operations on ciphertext to correspond to operations on plaintext.

Conceptually:

```text
Enc(10) + Enc(20)
```

produces a ciphertext that decrypts to:

```text
30
```

The party performing the addition never needs to know that the original values were `10` and `20`.

Similarly:

```text
Enc(10) * 5
```

can produce an encrypted value that decrypts to:

```text
50
```

The exact implementation is obviously much more complicated than this notation suggests.

Modern schemes rely heavily on lattice-based cryptography and polynomial arithmetic.

But we can understand the useful part without first deriving the mathematics.

---

## Is It Just Addition and Multiplication?

At first, this sounds surprisingly limited.

If all we can do is:

```text
+
*
```

how are we supposed to run useful programs?

The answer is that these operations are much more powerful than they initially appear.

Consider:

```text
3x² + 2x + 5
```

We can calculate it using only multiplication and addition.

A weighted score:

```text
0.5x₁ + 0.2x₂ + 0.3x₃
```

is also just multiplication and addition.

A dot product:

```text
x₁w₁ + x₂w₂ + x₃w₃
```

again consists of multiplication and addition.

From these building blocks we can construct things such as:

```text
Averages
Weighted scores
Variance
Dot products
Matrix operations
Linear regression
Parts of machine-learning models
```

CKKS implementations can also perform operations such as ciphertext rotations, which are useful when values are packed into encrypted vectors. OpenFHE's own examples demonstrate homomorphic addition, multiplication and rotations over packed values.

Things become more awkward when our program contains operations such as:

```python
if x > 50:
    ...
```

or:

```python
max(x, 0)
```

Comparisons and branching are not natural arithmetic operations in schemes such as CKKS.

Take ReLU:

```text
ReLU(x) = max(0, x)
```

Instead of evaluating `max()` directly, an HE application may approximate the function with a polynomial:

```text
ReLU(x) ≈ a + bx + cx² + dx³ + ...
```

And suddenly the problem is once again reduced to:

```text
+
*
```

Microsoft SEAL's maintainers similarly point to polynomial approximation as one approach for evaluating non-polynomial functions under CKKS.

This is an important limitation.

Homomorphic Encryption does not mean we can take arbitrary existing Python software, replace:

```python
x = 10
```

with:

```python
x = encrypted(10)
```

and expect everything to work.

Algorithms often have to be redesigned around operations that are efficient under encryption.

---

# Trying It in Python

Let's make this more concrete.

We will use **TenSEAL**, a Python library built around homomorphic encryption concepts provided by Microsoft SEAL.

Install it with:

```bash
pip install tenseal
```

We will use CKKS.

CKKS is particularly useful for approximate arithmetic over real-valued data.

First:

```python
import tenseal as ts
```

Now we create a context on the **client**.

```python
client_context = ts.context(
    ts.SCHEME_TYPE.CKKS,
    poly_modulus_degree=8192,
    coeff_mod_bit_sizes=[60, 40, 40, 60]
)

client_context.global_scale = 2**40
client_context.generate_galois_keys()
```

The exact meaning of these parameters deserves another article.

For now, the important part is that this context contains the cryptographic material needed for our CKKS operations.

Our secret dataset:

```python
salaries = [
    50000.0,
    72000.0,
    91000.0
]
```

We encrypt it:

```python
encrypted_salaries = ts.ckks_vector(
    client_context,
    salaries
)
```

At this point we have something the cloud can process without knowing the original values.

---

## Removing the Secret Key

This is the part that makes the demo interesting.

We do **not** want to send our complete client context to the cloud.

That would defeat the architecture.

Instead, we serialize a version without the secret key:

```python
server_context_bytes = client_context.serialize(
    save_public_key=True,
    save_secret_key=False,
    save_galois_keys=True,
    save_relin_keys=True
)
```

We also serialize the ciphertext:

```python
encrypted_salaries_bytes = encrypted_salaries.serialize()
```

These bytes represent what we could send to the compute server.

The server reconstructs its context:

```python
server_context = ts.context_from(server_context_bytes)
```

Let's verify something:

```python
print(server_context.has_secret_key())
```

The output should be:

```text
False
```

The server does not have our secret key.

TenSEAL's own serialization tests explicitly cover contexts serialized with the public and evaluation keys while omitting the secret key.

Now the server reconstructs the encrypted vector:

```python
server_salaries = ts.ckks_vector_from(
    server_context,
    encrypted_salaries_bytes
)
```

TenSEAL provides `ckks_vector_from()` specifically for loading a serialized CKKS vector and linking it with a context.

---

# Computing on the Server

Suppose we want to give every employee a 10% raise plus a fixed bonus of 1000.

In plaintext we would write:

```python
new_salary = salary * 1.10 + 1000
```

The server can perform exactly that arithmetic over our encrypted vector:

```python
encrypted_new_salaries = (
    server_salaries * 1.10
) + 1000
```

Notice what is missing.

There is no:

```python
decrypt()
```

The server never needs it.

It simply returns:

```python
result_bytes = encrypted_new_salaries.serialize()
```

---

## Can the Server Decrypt It?

Let's try.

```python
server_salaries.decrypt()
```

This should fail because the server context does not contain the secret key.

And that is exactly what we wanted.

Our compute node knows how to manipulate the ciphertext.

It does not know how to recover the plaintext.

---

# Back on the Client

The server sends us:

```text
result_bytes
```

The client still owns the original secret context.

So we reconstruct the result using it:

```python
encrypted_result = ts.ckks_vector_from(
    client_context,
    result_bytes
)
```

Now we can decrypt:

```python
result = encrypted_result.decrypt()

print(result)
```

Approximately:

```text
[56000, 80200, 101100]
```

There may be very small floating-point differences.

That is expected with CKKS because it performs approximate rather than exact arithmetic.

The complete flow was:

```text
CLIENT
------------------------------------------------

salary = [50000, 72000, 91000]

          |
          | encrypt
          v

ciphertext

          |
          | send
          v


SERVER
------------------------------------------------

secret key: NO

ciphertext

          |
          | * 1.10
          | + 1000
          v

new ciphertext

          |
          | send
          v


CLIENT
------------------------------------------------

new ciphertext

          |
          | decrypt
          v

[56000, 80200, 101100]
```

The server processed employee salaries without ever learning them.

---

# Simulating the Breach

Now imagine an attacker gains control of our cloud compute node.

They obtain:

```python
server_context
server_salaries
encrypted_new_salaries
```

They can even run:

```python
print(server_context.has_secret_key())
```

and get:

```text
False
```

They can copy the encrypted salary dataset.

They can inspect the process.

They can steal the server context.

But the secret key is simply not there.

That is a very different failure mode from:

```text
Server compromised
        ↓
Database dumped
        ↓
Customer records recovered
```

We have moved an extremely valuable asset — the ability to decrypt the data — outside of the compute environment.

Of course, key management now becomes critical.

If our client or key-holding service is compromised, the security boundary collapses.

Cryptography rarely removes trust completely.

More often, it lets us **move trust somewhere smaller and easier to defend**.

I think that is a much more useful way to think about Homomorphic Encryption.

---

# So Why Don't We Use This Everywhere?

Because this comes at a cost.

A normal CPU sees:

```python
42.0 * 1.10
```

and performs a tiny hardware operation.

Homomorphic Encryption sees something very different.

A ciphertext can contain large polynomial structures with thousands of coefficients.

Operations involve modular arithmetic over those structures.

So this:

```python
encrypted_salary * 1.10
```

is nowhere near as cheap as:

```python
salary * 1.10
```

The cost appears in several places.

## Compute

Encrypted arithmetic can be orders of magnitude more expensive than equivalent plaintext arithmetic.

Multiplication is particularly important because repeated multiplications increase the required computational depth.

Even Microsoft SEAL's documentation warns that two functionally equivalent HE implementations can differ in performance by **several orders of magnitude** depending on how the computation is structured.

So there is no useful universal number such as:

```text
Homomorphic Encryption = 100x slower
```

It might be acceptable for one workload and completely impractical for another.

---

## Memory

The number:

```text
42.0
```

can normally be represented with eight bytes as a double.

Its homomorphic ciphertext can be dramatically larger.

Instead of storing one tiny number, we are storing cryptographic objects containing large polynomial coefficients.

This also affects caches, RAM usage and serialization.

---

## Network

That same ciphertext expansion matters when sending data between machines.

Sending:

```text
1 MB plaintext
```

does not necessarily mean sending:

```text
1 MB ciphertext
```

Encrypted objects can be significantly larger.

For distributed applications, network cost can therefore become part of the performance equation.

---

# Multiplication Has Another Problem

There is another reason repeated multiplication matters.

Homomorphic ciphertexts contain noise.

Very roughly, imagine a ciphertext starting with:

```text
Useful signal: ███████████████████
Noise:         █
```

After more computation:

```text
Useful signal: ███████████████████
Noise:         █████
```

And after a sufficiently complicated computation:

```text
Useful signal: ███████████████████
Noise:         ███████████████
```

Eventually we risk losing the ability to recover a sufficiently accurate result.

In CKKS there is also the notion of levels and rescaling that controls how ciphertexts evolve through multiplication.

This is why the **multiplicative depth** of a program matters so much.

For example:

```text
x + x + x + x + x
```

is very different from repeatedly evaluating:

```text
((((x * x) * x) * x) * x)
```

The second expression creates a much deeper multiplication chain.

Microsoft SEAL's CKKS examples devote significant attention to managing scales and modulus levels for exactly this reason.

---

# Bootstrapping

Eventually we arrive at one of the most famous concepts in Fully Homomorphic Encryption:

**bootstrapping**.

Very roughly, bootstrapping refreshes a ciphertext so that further computation becomes possible.

You can think of it as turning:

```text
Ciphertext
Noise: █████████████
```

back into something closer to:

```text
Fresh Ciphertext
Noise: ██
```

without exposing the underlying plaintext.

This is one of the ideas that made Fully Homomorphic Encryption possible.

It is also expensive.

Modern FHE libraries therefore spend considerable effort optimizing bootstrapping, and OpenFHE exposes dedicated CKKS bootstrapping functionality and examples.

We will leave the mathematics behind that for another time.

---

# FHE Is Not a Magic Breach Shield

There is one important warning to end with.

It is tempting to think:

> If everything is encrypted while being processed, compromising the server no longer matters.

That would be wrong.

Homomorphic Encryption protects a specific security boundary.

An attacker may still:

```text
Modify computations
Steal metadata
Observe access patterns
Exploit the surrounding application
Compromise the key holder
Manipulate input or output
Attack another component that receives plaintext
```

And the exact threat model matters.

For example, OpenFHE explicitly documents security assumptions around its homomorphic schemes and notes that its standard schemes are primarily designed around an honest-but-curious/semi-honest model unless additional protections are applied.

So the interesting statement is not:

> Homomorphic Encryption makes breaches safe.

It is:

> Homomorphic Encryption can allow a compute system to perform useful work without giving that system the secret required to read the underlying data.

That dramatically changes what an attacker can obtain by compromising that particular system.

---

# Conclusion

The thing I find most interesting about Homomorphic Encryption is not the fact that:

```text
Enc(5) + Enc(10)
```

can result in an encryption of:

```text
15
```

That is a nice cryptographic trick.

The more important idea is architectural.

Normally, giving a server the ability to process sensitive information also means trusting that server with the sensitive information.

Homomorphic Encryption allows us to begin separating those two permissions:

```text
Permission to compute

does not necessarily imply

Permission to read
```

That is a powerful security primitive.

We pay heavily for it in compute, memory, bandwidth and complexity.

But for systems handling sufficiently sensitive information, the tradeoff starts to become very interesting.

Especially when the question changes from:

> How do we stop the server from being breached?

to:

> What can we design so that even a breached server does not have everything the attacker wants?

That is where Homomorphic Encryption gets interesting.


## References

The following resources are useful for going deeper into the concepts discussed in this article:

1. **Microsoft SEAL**  
    Microsoft Research's open-source homomorphic encryption library and one of the main libraries behind practical CKKS and BFV implementations.  
    [https://github.com/microsoft/SEAL](https://github.com/microsoft/SEAL)
2. **Microsoft SEAL — CKKS Basics Example**  
    A practical introduction to CKKS, including encoding, scales, modulus levels, multiplication, rescaling and ciphertext management.  
    [https://github.com/microsoft/SEAL/blob/main/native/examples/5_ckks_basics.cpp](https://github.com/microsoft/SEAL/blob/main/native/examples/5_ckks_basics.cpp)
3. **TenSEAL**  
    A Python-friendly homomorphic encryption library built on top of Microsoft SEAL. TenSEAL provides encrypted vectors and tensors and is particularly convenient for experimentation with CKKS.  
    [https://github.com/OpenMined/TenSEAL](https://github.com/OpenMined/TenSEAL)
4. **TenSEAL: A Library for Encrypted Tensor Operations Using Homomorphic Encryption**  
    Ayoub Benaissa, Bilal Retiat, Bogdan Cebere, Alaa Eddine Belfedhal.  
    The paper describes TenSEAL and demonstrates privacy-preserving machine-learning workloads using homomorphic encryption.  
    [https://arxiv.org/abs/2104.03152](https://arxiv.org/abs/2104.03152)
5. **OpenFHE Documentation**  
    OpenFHE is another major open-source FHE library. Its documentation includes examples covering homomorphic arithmetic, packed ciphertexts, rotations and several modern schemes.  
    [https://openfhe-development.readthedocs.io/](https://openfhe-development.readthedocs.io/)
6. **OpenFHE CKKS Bootstrapping Example**  
    An implementation-level example showing CKKS bootstrapping, one of the fundamental techniques used to enable deeper homomorphic computations.  
    [https://openfhe-development.readthedocs.io/en/latest/api/program_listing_file_pke_extras_ckks-bootstrap.cpp.html](https://openfhe-development.readthedocs.io/en/latest/api/program_listing_file_pke_extras_ckks-bootstrap.cpp.html)
7. **CKKS Explained — OpenMined**  
    A useful series explaining the CKKS scheme from the encoding layer upward, including the mathematical intuition behind approximate homomorphic arithmetic.  
    [https://openmined.org/blog/ckks-explained-part-1-simple-encoding-and-decoding/](https://openmined.org/blog/ckks-explained-part-1-simple-encoding-and-decoding/)
8. **CKKS.org**  
    A collection of resources about the CKKS homomorphic encryption scheme, including its use for approximate real and complex-number computations.  
    [https://ckks.org/](https://ckks.org/)
9. **CryptoNets: Applying Neural Networks to Encrypted Data**  
    One of the earlier influential works demonstrating neural-network inference directly over encrypted data.  
    [https://arxiv.org/abs/1412.6181](https://arxiv.org/abs/1412.6181)

