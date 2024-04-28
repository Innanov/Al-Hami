## TLS协议

省略了证书验证，密码算法协商等步骤，直接开始密钥交换

### client

1. 连接后，client发送密钥交换申请，操作码：1
2. 收到server的公钥后，构造Pb和m，完成key mismatch攻击，并计算出对称密钥KB，将Pb，c1，c2发送给server，操作码：3
3. 收到server的加密消息后，尝试使用自己的对称密钥解密，如果解密成功，则说明oracle=1，否则，oracle=0，申请终止对话，操作码：0。

这样就完成了一次query。

### server

1. 连接后，收到client的密钥交换申请，产生公私钥对，将不变的公钥发送给client，操作码：2
2. 收到client的Pb，c1，c2，计算出自己的对称密钥KA，发送一条加密的“hello”消息，操作码：4