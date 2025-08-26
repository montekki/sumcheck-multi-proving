An example code showing how to run sum-check implementations over Goldilocks field with implementations from two libraries:
 * [`scroll-tech/ceno`](https://github.com/scroll-tech/ceno)
 * [`icicle`](https://github.com/ingonyama-zk/icicle)

   
The current problem is that the `icicle` library is [missing](https://github.com/ingonyama-zk/icicle/issues/1032) the implementations for sum-checks over extension fields
however, as long as the two protocols have values that remain within the base field, they yeild the same outputs (meaning, that the two implementations can be run interchangeably):

```
[2025-08-26T13:46:13Z INFO  sumcheck_multi_proving] verify time 1.176041ms [[0x863475a602c2ef45, 0x9d7c9b52e56be055, 0x66638a60ee666b88, 0x474ebc91b813ba9d], [0xf49a7b912366a82b, 0xa6ebc9e85a5d029e, 0x603ff3554c93bd65, 0xd65598c3222ce65b]]
[2025-08-26T13:46:13Z INFO  sumcheck_multi_proving] ceno proof [[863475a602c2ef45, 9d7c9b52e56be055, 66638a60ee666b88, 474ebc91b813ba9d], [0, 0, 0, 0]]

```
