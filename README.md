## Bulletproofs Gadgets

Zero knowledge proofs using the [Java Bulletproofs implementation](https://github.com/weavechain/bulletproofs).

Bulletproofs are short non-interactive zero-knowledge proofs that require no trusted setup. 

[Read More about Bulletproofs](https://crypto.stanford.edu/bulletproofs/)

[Paper](https://eprint.iacr.org/2017/1066.pdf)

Partially based on the [Rust implementation](https://github.com/lovesh/bulletproofs-r1cs-gadgets) by Lovesh Harchandani


### Gradle Groovy DSL
```
implementation 'com.weavechain:bulletproofs-gadgets:1.0'
```

### Gradle Kotlin DSL

```
implementation("com.weavechain:bulletproofs-gadgets:1.0")
```

#### Apache Maven

```xml
<dependency>
  <groupId>com.weavechain</groupId>
  <artifactId>bulletproofs-gadgets</artifactId>
  <version>1.0</version>
</dependency>
```

### Usage

Few usage samples below:

##### Number In Range

```java
NumberInRangeParams params = new NumberInRangeParams(
        10L,
        100L,
        31
);

Long value = 16L;

PedersenCommitment pc = PedersenCommitment.getDefault();

Scalar rnd = Utils.randomScalar();
BulletProofGenerators bg1 = new BulletProofGenerators(128, 1);
Proof proof = bulletProofs.generate(GadgetType.number_in_range, value, params, rnd, pc, bg1);

Proof proof2 = Proof.deserialize(proof.serialize());

BulletProofGenerators bg2 = new BulletProofGenerators(128, 1);
boolean match = bulletProofs.verify(GadgetType.number_in_range, params, proof2, pc, bg2);
System.out.println(match ? "Success" : "Fail");
```

##### Numbers Sum To

```java
NumbersSumToParams params = new NumbersSumToParams(10L, 4, 10);

List<Long> values = List.of(1L, 2L, 3L, 4L);

PedersenCommitment pc = PedersenCommitment.getDefault();

Scalar rnd = Utils.randomScalar();
BulletProofGenerators bg1 = new BulletProofGenerators(128, 1);
Proof proof = bulletProofs.generate(GadgetType.numbers_sum_to, values, params, rnd, pc, bg1);

Proof proof2 = Proof.deserialize(proof.serialize());

BulletProofGenerators bg2 = new BulletProofGenerators(128, 1);
boolean match = bulletProofs.verify(GadgetType.numbers_sum_to, params, proof2, pc, bg2);
System.out.println(match ? "Success" : "Fail");
```


##### Number In List

```java
NumberInListParams params = new NumberInListParams(List.of(1L, 3L, 128L, 145L), 8);

Long value = 128L;

PedersenCommitment pc = PedersenCommitment.getDefault();

Scalar rnd = Utils.randomScalar();
BulletProofGenerators bg1 = new BulletProofGenerators(128, 1);
Proof proof = bulletProofs.generate(GadgetType.number_in_list, value, params, rnd, pc, bg1);

Proof proof2 = Proof.deserialize(proof.serialize());

BulletProofGenerators bg2 = new BulletProofGenerators(128, 1);
boolean match = bulletProofs.verify(GadgetType.number_in_list, params, proof2, pc, bg2);
System.out.println(match ? "Success" : "Fail");
```

#### Weavechain

Weavechain is a Layer-0 for Data, adding Web3 Security and Data Economics to data stored in private vaults in any of the traditional databases.

Read more on [https://docs.weavechain.com](https://docs.weavechain.com)