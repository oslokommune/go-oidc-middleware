package testing

const TEST_PRIVATE_KEY = `
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDox9f4Vpcj6cNj
KZcOuEQWIjFnraO4D908xcoeTIGIi1VsOMD9+2yZ7LkVWhLxkQ1ZMsQo1U4qu2CC
vhomA8yboV2QGe7C3A6Pj/Y6SArhT1QhRyIivf5LIZY0+NjxRc3GZRavIfXpvGg2
Ti6QFp41fS4tgtVHNVzEM4wpbTO2stDiaP7lJT2s2PxmrIft8U/kHq3gB/ldXPsz
1NzOnf6AoLH6Mv99x3ILrAR/vP+J3tm+Yodhmo7BrR+16PZS/SAs/TgMoFeppt0e
C4RHGp9WR9M7F4ISQn/qKfellXA5lfci7p7PVOAoIk8JFrBXxR0aygiktCjpnplI
HyYtNJ6zAgMBAAECggEBAM76yzU8wT0koSAuHevvulK36pgWlEmYiY59DB/uxQrF
YZpNyITNJ56iF1w98DQtVuImOrdYGx3x6Hm4UQXWQPts+wWjmWJYSvYp+rWN02bN
o6/HUTn1GAR0A9xsHHJEMBklT4s/tioz5bHLyKlEAz7qZMIA4GVltGucrhczy1S5
btWfOI3X0UwiEEuhBLu0Nv5zPTo4OmpeQatbM6PaXRj954BAuLB5SNgolVnOn8xd
KtVMSFNqDGfQQHZSJrrVv97ZkkOotTrZWzv08K9xYTH91UNXohH28uQ3opzj5tN6
8Fnt/O4qMpTfKeeToWuZ2tXEv8N2cQ+n4g5Itjg7HVECgYEA9Gqn7Gq4HHXQUUBk
YXSajBli2NmycabuSZUSS8xUfOI+ZXrmFwyjgSKnEUcL90ZizTCehxOdRYq8LxBr
klcCavzM4p7JqBTqzfnCHpq1U3oairX7ZqZurIbCbHA+do8SjOtVewACh7ceNElz
TXJRO2TreXsdtvZpdZC1FJzfFRsCgYEA89AEGf+71g/qfYhkU33PtEbkExESwaIb
XXREF9MZxV0E0Mg1JDfc8mklpVNOHT7EOiA7SOJ3XNf6CXXsQCdzlMuQA+euiaTd
EZL70PpcKiVKl9CefjKhBj4FaT9NEw1dJbCGp34ohi2J9ZRfWsN8//er2N+kUPdR
3OuxhBnybkkCgYBa2Wohjmlw6rnL+ctWDimD+cusHv8dD5dy8l4inoipAs9+mPf9
iU0dKuw+l9Hyz87ZxkCmpLvIpZDdTZUuh/j2G5FsiukZ+OxuM2/cQFU1+iTzekFA
Hoz0xAJwnCgbmYKjrrXPSmmmWIJ5nPOmzd8z3IdKWGDrKRx5/pfQWZ7yEQKBgBB+
2Ggx5zF6bjEEE1Waw3y89x1bIFu9bgCKpzi9bZbuzi6Z/Q5wQSCdgJCI7FYKMxiD
qb8qo0zCyAXv1oYYpTdB9oJtIF/rqZFQ0ny3E5k+YKeY08BSCJb1h0QxpjNNyimM
oe+fF3rMhfL5kOIBK+ndheDscJ+RvBYoVCBN6RsRAoGALB2XylHyavhrKrldFCWR
fLCSe9M4bxS2/mV8lTf+x+OAZaJzh/66p3i7xigIrQTHpowzSxkG4D9nay1zQYKi
6RIlI9HbNm/Mybk8MDHUVfiCxAQNx4g60MwHzP25IpizkY7/1/bzKIO4fuu9Hd4l
Y6pCW3Sh7RMvjNI2EK9Knrw=
-----END PRIVATE KEY-----
`

const TEST_PUBLIC_KEY = `
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6MfX+FaXI+nDYymXDrhE
FiIxZ62juA/dPMXKHkyBiItVbDjA/ftsmey5FVoS8ZENWTLEKNVOKrtggr4aJgPM
m6FdkBnuwtwOj4/2OkgK4U9UIUciIr3+SyGWNPjY8UXNxmUWryH16bxoNk4ukBae
NX0uLYLVRzVcxDOMKW0ztrLQ4mj+5SU9rNj8ZqyH7fFP5B6t4Af5XVz7M9Tczp3+
gKCx+jL/fcdyC6wEf7z/id7ZvmKHYZqOwa0ftej2Uv0gLP04DKBXqabdHguERxqf
VkfTOxeCEkJ/6in3pZVwOZX3Iu6ez1TgKCJPCRawV8UdGsoIpLQo6Z6ZSB8mLTSe
swIDAQAB
`

func newTestingSecret() *TestingSecret {
	return &TestingSecret{
		Kid:        "YuVE7NMysNukHraL8sI0jkyGbhEWWB8zjyInBfG_cBw",
		PrivateKey: TEST_PRIVATE_KEY,
		PublicKey:  TEST_PUBLIC_KEY,
		Kty:        "RSA",
		E:          "AQAB",
		Use:        "sig",
		Alg:        "RS256",
		N:          "6MfX-FaXI-nDYymXDrhEFiIxZ62juA_dPMXKHkyBiItVbDjA_ftsmey5FVoS8ZENWTLEKNVOKrtggr4aJgPMm6FdkBnuwtwOj4_2OkgK4U9UIUciIr3-SyGWNPjY8UXNxmUWryH16bxoNk4ukBaeNX0uLYLVRzVcxDOMKW0ztrLQ4mj-5SU9rNj8ZqyH7fFP5B6t4Af5XVz7M9Tczp3-gKCx-jL_fcdyC6wEf7z_id7ZvmKHYZqOwa0ftej2Uv0gLP04DKBXqabdHguERxqfVkfTOxeCEkJ_6in3pZVwOZX3Iu6ez1TgKCJPCRawV8UdGsoIpLQo6Z6ZSB8mLTSesw",
	}
}
