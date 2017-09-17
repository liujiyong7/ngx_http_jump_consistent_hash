# 名字

ngx_http_jump_consistent_hash

# 描述
ngx_http_jump_consistent_hash是一个实现了jump consistent hash算法的nginx模块。
jump consistent hash是一种一致性哈希算法, 此算法零内存消耗，均匀分配，快速，并且只有5行代码。

论文原文见：https://arxiv.org/ftp/arxiv/papers/1406/1406.2294.pdf 

# 如何使用

jump_consistent_hash
---------------------
**syntax:** *jump_consistent_hash $variable*

**context:** *upstream*

在upstream上下文中，使用 jump_consistent_hash 指令，即可打开jump consistent功能

示例

```
upstream test_consistent {
	jump_consistent_hash $request_uri;

}
```
