
import os
import re
from pathlib import Path


def mkdir(path, parents=False):
    try:
        Path(path).mkdir(parents=parents)
    except FileExistsError:
        # not a problem
        pass

def create(path, filename, data, force):
    if not force:
        if (path / filename).exists():
            return
    with open(str(path / filename), 'w') as f:
        f.write(data)

def symlink(path, filename, domain, num, recreate):
    if recreate:
        try:
            (path / '{}.pem'.format(filename)).unlink()
        except FileNotFoundError:
            # fine
            pass
    (path / '{}.pem'.format(filename)).symlink_to(
                '../../archive/{}/{}{}.pem'.format(domain, filename, num))


class Handler:
    def __init__(self):
        self.errors = []
        self.warnings = []

    def warning(self, obj):
        self.warnings += [ obj ]

    def error(self, obj):
        self.errors += [ obj ]


def create_testing_base_dir(
        base='.alnitak_tests', le_dir='etc/le',
        domains={
            'a.com': [
                '''MIIClzCCAgCgAwIBAgIJALZnNWR3/N7aMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNV
BAYTAkdCMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxvbmRvbjEQMA4GA1UE
CgwHQWxuaXRhazEQMA4GA1UECwwHdGVzdGluZzEOMAwGA1UEAwwFYS5jb20wHhcN
MTkwMTI0MTQ0MjQ4WhcNMTkwMjIzMTQ0MjQ4WjBjMQswCQYDVQQGEwJHQjEPMA0G
A1UECAwGTG9uZG9uMQ8wDQYDVQQHDAZMb25kb24xEDAOBgNVBAoMB0Fsbml0YWsx
EDAOBgNVBAsMB3Rlc3RpbmcxDjAMBgNVBAMMBWEuY29tMIGfMA0GCSqGSIb3DQEB
AQUAA4GNADCBiQKBgQDgODlws5tZjrIX4J52erhkaBRrnCSwE24wVAedh4piIR4u
e5W3H/Z5DQo2nqKMhNo2magaaBNsDUGyRdg3H8nLLtPDPtAmN41VxMerWySDNwNn
43O7Y56iAODz1Nk7IHHzEOUZ9R/XhUB+KSxkkog9fo2T/lVFWJnqIcxWqPpp1QID
AQABo1MwUTAdBgNVHQ4EFgQUjbLDXEncsRtPPw7RGPtuX0r3+9UwHwYDVR0jBBgw
FoAUjbLDXEncsRtPPw7RGPtuX0r3+9UwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG
9w0BAQsFAAOBgQCv+jXJQ1MtABAMswyaI+S8jnhgSzy3KrsUAhyt+BekBHZtt4bI
2MjA7QgbI0vQT4D7g4WQLnW3QIaQ6c1lqO8h835bCWQHMR6H4orvWL4SJDBsvGiK
/+YrW4Mx0VVrwJbnbAJ+thUWPxswtOmI/NQsth1D6neL5TTwDBmQuowZtg==''',
                '''MIIClzCCAgCgAwIBAgIJAIxNFzKotLgrMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNV
BAYTAkdCMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxvbmRvbjEQMA4GA1UE
CgwHQWxuaXRhazEQMA4GA1UECwwHdGVzdGluZzEOMAwGA1UEAwwFYS5jb20wHhcN
MTkwMTI0MTQ0MTQ3WhcNMTkwMjIzMTQ0MTQ3WjBjMQswCQYDVQQGEwJHQjEPMA0G
A1UECAwGTG9uZG9uMQ8wDQYDVQQHDAZMb25kb24xEDAOBgNVBAoMB0Fsbml0YWsx
EDAOBgNVBAsMB3Rlc3RpbmcxDjAMBgNVBAMMBWEuY29tMIGfMA0GCSqGSIb3DQEB
AQUAA4GNADCBiQKBgQDyZip4bFrvS6g1wr8M6jV72Z7d9vlZpOAxgG7g2mFesXaO
fybJbEQfCeUKvlH2pO/a7RuED1xGXJX/WtLudWiO0Hq9ExVSwhx9OOugKZFG2cWa
DTAGgON/G8Xr+OkDZXqUK7JOqgcy0NK4MbX9Pv28yWbQ7Kg+Bhw0Zx99O1l8YQID
AQABo1MwUTAdBgNVHQ4EFgQUQirr13cp3DH4s+riBG/sy7NnxmIwHwYDVR0jBBgw
FoAUQirr13cp3DH4s+riBG/sy7NnxmIwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG
9w0BAQsFAAOBgQA+zXSP+DG+tuZ5fKhZfSh58LntTVM3zZbzEA85LsVu3u+walX8
3XpzgKpBdzKZOgeUNldobv/OgkpIBjCVi3q4Qu44FrEwUlVDQDjGttSignF+ua2X
DLmeZk81zhKrghOOqx/IzBLcMWpOHgFHGXesVKatwcbenAUfv7oUe7XpKQ==''',
                '''MIIFnDCCA4SgAwIBAgIJAM1Y9xn8zUn5MA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNV
BAYTAkdCMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxvbmRvbjEQMA4GA1UE
CgwHQWxuaXRhazEQMA4GA1UECwwHdGVzdGluZzEOMAwGA1UEAwwFYS5jb20wHhcN
MTkwMTI0MTQwODM1WhcNMTkwMjIzMTQwODM1WjBjMQswCQYDVQQGEwJHQjEPMA0G
A1UECAwGTG9uZG9uMQ8wDQYDVQQHDAZMb25kb24xEDAOBgNVBAoMB0Fsbml0YWsx
EDAOBgNVBAsMB3Rlc3RpbmcxDjAMBgNVBAMMBWEuY29tMIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEAwRa51lpxV3BvidBJ7Jh0cuMwdRVzAo2gSA0QznY+
SgX1L5VABq92RbH45pUQzCQCl1Unn2/q4zYhP16xIJw400UrMky8xIMDxphmhAPT
dnXm0fXkHMDPAbBARYhrMmd1l8C+kTGAqgqFViV4yk+203/siIfKOAsJUgLwRuaw
VKB6VMexZYnhq4njJk+ICPivPbpR6C+3cp8B5t/eAFhc5IHZreqTyYqVJnyb9RpF
W3xi7O0eFN8nVgIuCGo5Ci9m988I2HouoSZeP74PbvpuqOYRg6EfYSJuUeskzQcy
zb50Cxh4wB2x2LNQZD/1UyGHxXmwBRZaXUmrbJFUdhJAtAku9mVZHJiejgrl2jxe
VQsspVBh06FBkwSEfEoAjELC9Yp1JZHX6m0AzQI/gIwF3dpePkEOiboEOWe86C1a
AGoVjeoYkdNILqvBUOZwum5J83s+xgO2T0c3IYTwQwVor/it+1eRlyPcu7PWUH1K
0+p0e/Xvt6+CHCvokjcLM6O9q/lKh4NN+TIZo6COeFFKF+uEYXGLzOWzaiz16afP
lk0OkAnJZ1uTiraCGyvuOM7yG5v0VVprEJLq/6K45fLh70Lhae8CdMiJiyGANDhI
lLoh1OpI7LBIaSJflSVlzoGOGFA9hqy+ecpE14Ii3B+HiULDzbzYfDD1FqjJPkcV
AvkCAwEAAaNTMFEwHQYDVR0OBBYEFM5bXWTBirflDXxkUpUOUoGJzQagMB8GA1Ud
IwQYMBaAFM5bXWTBirflDXxkUpUOUoGJzQagMA8GA1UdEwEB/wQFMAMBAf8wDQYJ
KoZIhvcNAQELBQADggIBAHYw6qjM7ZJAr2k8+Vc9SSa1xqOhAmMjsa8OVkkH1m+1
l48NINwvcJ5CUHe/Rn5grFzatNy1XgiL4zhD4LmIZS2UhKIf16NphWYBDArg1ut+
8/agVojUneNTiYIkyL5+cPZK/58ChdKyeqZgKSfdzhiIP1nMzsigitOTtXk/fCxG
phucu7Ojpmu+tpPKwNLjengeLCOhnvjY8Xc94WVgGXY2OmCJnZQdBvK8ZA/PDtkb
6YQQWU6DWZGXQhlLmmKpZHuqEE/Fb2+0mB4vK99eAgdxr6Mv7cz3WCT/P1ikP6HA
6QJl1FR0fDjibeJbjJMaRjPr9oVf/aGoS8TP0FlAifVVNAoieZtXncD99bsT/Ltl
nN9lXmkk/pi5YHIwRZrWtIgn374MlaNuoHanmA6FgSqtAwl1Nv8xFbc4lAbq4VaA
eBPls0nRUjHS55nGaPZEhMI4J/9xUMDRn+wOMZHXisHgHPU/6MfiONDobVNxL4E+
h0+47d7xJfWNZmFPm/8Nk36J2R0mevY1ERLw5+sLPGnwJnGCLSG5mLsNBQtSvSTa
ixYV/T1qkcsoDoJTEnkclHskXDY9rN6iJvhMlV6cdR8QWYFH3vc5OPrIKHf+1x+x
zKOVPpVoRmQefxXd/ro/gHLoZO89YhzmjfYkQgjb9akbFvGLAHMX9IsGoMcqHWGZ''',
                ],
            'b.com': [
                '''MIIClzCCAgCgAwIBAgIJAIzZ6W1XJFyCMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNV
BAYTAkdCMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxvbmRvbjEQMA4GA1UE
CgwHQWxuaXRhazEQMA4GA1UECwwHdGVzdGluZzEOMAwGA1UEAwwFYi5jb20wHhcN
MTkwMTI0MTQ0NTU5WhcNMTkwMjIzMTQ0NTU5WjBjMQswCQYDVQQGEwJHQjEPMA0G
A1UECAwGTG9uZG9uMQ8wDQYDVQQHDAZMb25kb24xEDAOBgNVBAoMB0Fsbml0YWsx
EDAOBgNVBAsMB3Rlc3RpbmcxDjAMBgNVBAMMBWIuY29tMIGfMA0GCSqGSIb3DQEB
AQUAA4GNADCBiQKBgQDMzl8BOijFQRb8gQOR0QLLr1jC3Wy7QSCOFEnm+LZUH6iE
BG6zSiA62j4zvEDRp1MGgqq+sUHBBr6laWXkR08ksQd6u7fVTmJLYD8sJc+wOu7y
UJOx9LJJuGqUR8XJ6Q0J6o0366YBUX3Ms48OPULtNjoCGcUJdyqwhbb6sfSKYQID
AQABo1MwUTAdBgNVHQ4EFgQU9ECkhmNz9f184LIMeuu18wr10Z8wHwYDVR0jBBgw
FoAU9ECkhmNz9f184LIMeuu18wr10Z8wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG
9w0BAQsFAAOBgQCA5ieKY4XecJXhhmtx7KKPVBse9aTmlYHKoWWwpTb+fDuOXyO4
khVaEZmRXztt6iNgR2sgwUMVAZVjACVb16e8i3gnGFS6UjGzfhax8pAVzd/Xnjil
ej0Oa800hKUOsxAS+5YfR0WmEWaA2u5TfX34++V2lyrCqji42nLvZnH/nQ==''',
                '''MIIClzCCAgCgAwIBAgIJAJJvdZ99n2EiMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNV
BAYTAkdCMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxvbmRvbjEQMA4GA1UE
CgwHQWxuaXRhazEQMA4GA1UECwwHdGVzdGluZzEOMAwGA1UEAwwFYi5jb20wHhcN
MTkwMTI0MTQ0NjIxWhcNMTkwMjIzMTQ0NjIxWjBjMQswCQYDVQQGEwJHQjEPMA0G
A1UECAwGTG9uZG9uMQ8wDQYDVQQHDAZMb25kb24xEDAOBgNVBAoMB0Fsbml0YWsx
EDAOBgNVBAsMB3Rlc3RpbmcxDjAMBgNVBAMMBWIuY29tMIGfMA0GCSqGSIb3DQEB
AQUAA4GNADCBiQKBgQC5N+IyRFmPOfBRffzzilmLU2LUhOG8g6eZ+k4qlU6z+gto
H1fu38nt7i0M2/3CuYkBoXKQwgiedP5vITdscUgLkClVLZJ2YaB5t5t429u7qZEC
Bs+JVRKLV/7fRfGLRdCiIsXOYMMeekn6yW/cVYI5WPiysFhs93dFyIBVAqkPPwID
AQABo1MwUTAdBgNVHQ4EFgQUIvZFklIHwNZFeIUns5/SBDDFoMYwHwYDVR0jBBgw
FoAUIvZFklIHwNZFeIUns5/SBDDFoMYwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG
9w0BAQsFAAOBgQAUqjTWBxGu7WJTkav2sE0fu2KxBLuGerSt8SQSOwYChjN/bKXl
ys/wHHGrrhZ4wp/78LUKzCj3VB4PzU878h6JEUgsdbk0oUvM4TuZctv6DdXVEGnI
rdRRLb7m3uy677OejoMzU4v+GnaKGdWJ4A7PFz09Vv1rsSneinkdVLsh3g==''',
                '''MIIDnDCCAoSgAwIBAgIJALYVFUDe4r+3MA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNV
BAYTAkdCMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxvbmRvbjEQMA4GA1UE
CgwHQWxuaXRhazEQMA4GA1UECwwHdGVzdGluZzEOMAwGA1UEAwwFYi5jb20wHhcN
MTkwMTI0MTQ0MzU2WhcNMTkwMjIzMTQ0MzU2WjBjMQswCQYDVQQGEwJHQjEPMA0G
A1UECAwGTG9uZG9uMQ8wDQYDVQQHDAZMb25kb24xEDAOBgNVBAoMB0Fsbml0YWsx
EDAOBgNVBAsMB3Rlc3RpbmcxDjAMBgNVBAMMBWIuY29tMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEA0wmxH1uULHFbavYP8UrcDz9EbC2DZusuoC+iH83i
9a2F+yA2ReIX6vHXpobDf2h67S5CF85eca7B5viGnwil5IcbxkieWeK/98EtgpT6
4z6KU2tPFNL3NeRuyaKwh6AlwpHkE/JCbrqzJlqlaqrBOk+M3UuVbLLlFVHNdXIT
AfzFfWVWZSfdRSk3pMST2l57Y1U62RjiJGrRekxHCtzt3URmGhs2nREFq3CjyAtw
Q6+nbsBK1zcDzD7dTF7FQuc6LgVnfN91KztRVM4EERvKDIf2XwJbQ5wtX2j7ZVKe
+kudy4RhnKWyEqiIYpMgP8mgBZORem59uLjuiKFKM+5ABQIDAQABo1MwUTAdBgNV
HQ4EFgQUBWMGPLNrokNjuULhh/mfu/ixGJEwHwYDVR0jBBgwFoAUBWMGPLNrokNj
uULhh/mfu/ixGJEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEA
o1czBGmQW7mr2LVokwc2JTB1EH/2F5fFsxq5MhXDa7CKojDGjN4y/zwZuGW7/vk3
YSMsyx/fWP3HMFe73gaqMXUwAxcTNPXv5CRNA6BjP0uR6Fz04+6l9s3tCMozljQT
coccJNzzgdScaoLAi2fMSoLn2oB/Evjh0/ntktItTqpRuVeNFCj/wsKQhsx9qUZG
EiEUepJOeqHPgxx2nI8KQJMXkIgvgjkYWlIZJyPpCNXe0BRupeM1q6Sbtgw2aL3B
aiOnv52z0x1f4TzRGtSm35lttRj+GW0IQ3+8UCKPZ3QfjJRzFQxBrj9P5rHgDOyY
8yCjesxjTbFBQY+hiKdXbQ==''',
                ],
            'c.com': [
                '''MIIClzCCAgCgAwIBAgIJAPxBy0EvAnFsMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNV
BAYTAkdCMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxvbmRvbjEQMA4GA1UE
CgwHQWxuaXRhazEQMA4GA1UECwwHdGVzdGluZzEOMAwGA1UEAwwFYy5jb20wHhcN
MTkwMTI0MTQ0NTM2WhcNMTkwMjIzMTQ0NTM2WjBjMQswCQYDVQQGEwJHQjEPMA0G
A1UECAwGTG9uZG9uMQ8wDQYDVQQHDAZMb25kb24xEDAOBgNVBAoMB0Fsbml0YWsx
EDAOBgNVBAsMB3Rlc3RpbmcxDjAMBgNVBAMMBWMuY29tMIGfMA0GCSqGSIb3DQEB
AQUAA4GNADCBiQKBgQCyeITh7Wxf8EtXTAx3ugQRouW/5caBd3gvFkyc7F/z1Bcp
mrC4giBanJrjOTxTzOqYRNcfRFMSXI5EjhLAEaVY5yN3dxLh38aEFCWYYYUCmE+5
4gI5vQQlV2XbjYNFMSeio5dBUOnx/H9ecfKaqVklpOV27SJ+cuERrGAHL4e0ZwID
AQABo1MwUTAdBgNVHQ4EFgQUqPaAw0ck30tqGJsg1tBsJmqN+n4wHwYDVR0jBBgw
FoAUqPaAw0ck30tqGJsg1tBsJmqN+n4wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG
9w0BAQsFAAOBgQAO0eDZ8L4thFnk/8RbQexS3RmBq97WX1dSYpViCFGynXuxWkg5
v3NZ1c1KXIZF757RSEJgKjJ8ujE7v557gy2SeVzsdofyG23DK7G9F66UR344YQmK
qdPHHd8julm6pWJ0ZwTS0a+pSmH1jWlOYx1AQjKEe0RJtnnqbBd3F4vkNQ==''',
                '''MIIClzCCAgCgAwIBAgIJAIC6WRCPtu8LMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNV
BAYTAkdCMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxvbmRvbjEQMA4GA1UE
CgwHQWxuaXRhazEQMA4GA1UECwwHdGVzdGluZzEOMAwGA1UEAwwFYy5jb20wHhcN
MTkwMTI0MTQ0NTExWhcNMTkwMjIzMTQ0NTExWjBjMQswCQYDVQQGEwJHQjEPMA0G
A1UECAwGTG9uZG9uMQ8wDQYDVQQHDAZMb25kb24xEDAOBgNVBAoMB0Fsbml0YWsx
EDAOBgNVBAsMB3Rlc3RpbmcxDjAMBgNVBAMMBWMuY29tMIGfMA0GCSqGSIb3DQEB
AQUAA4GNADCBiQKBgQCw2Zs4ZIgCfLKFNcM6m9YaU+aJkWOacWH7jglEGJemfLl0
z4EZpdJZMhuujDF4oeWPAjGf3ixTH1uxYVkikvvt3NrdH4rQQmWOqgYQ5ZMmNNMu
plrO0RNphYn+wL3Cq8Rv4eqj9LndIfrxKrgGHujUo1ig25ZzhdqgmR40bjjOnQID
AQABo1MwUTAdBgNVHQ4EFgQUOVLYJcwQbmJUX/6ZjiZ9zcKXhigwHwYDVR0jBBgw
FoAUOVLYJcwQbmJUX/6ZjiZ9zcKXhigwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG
9w0BAQsFAAOBgQCbBofLi+fOzD0iwjrTYaL4o0gp4U2H8i35N/1+Ku5mJUv5tWNE
ypeWjdubhk2bxBR/Q26/N2+uACR87+3CBVeEJyTfFdQtrgHjE5QHNn3Ju1aI2lZj
pUbuhIhvKzM48pgoqJMMLDWgtK+hxnb5nWW01hhb6JiXeJWCx3keqxt00A==''',
                '''MIIDnDCCAoSgAwIBAgIJAJrsYibODwN4MA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNV
BAYTAkdCMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxvbmRvbjEQMA4GA1UE
CgwHQWxuaXRhazEQMA4GA1UECwwHdGVzdGluZzEOMAwGA1UEAwwFYy5jb20wHhcN
MTkwMTI0MTQ0NDE2WhcNMTkwMjIzMTQ0NDE2WjBjMQswCQYDVQQGEwJHQjEPMA0G
A1UECAwGTG9uZG9uMQ8wDQYDVQQHDAZMb25kb24xEDAOBgNVBAoMB0Fsbml0YWsx
EDAOBgNVBAsMB3Rlc3RpbmcxDjAMBgNVBAMMBWMuY29tMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEArfMaxw2afbW0l00wP3Lr6K+T66CesSmv5ZToJSA1
ok9cOn+4Dp195y8zCZPHizE3daw4Ymgvnv9g/Tt6NGVsOaI+b1hr5XGUzUyOOZK/
ffcOuoww7+SedbF94pVQ+cC5rUA1x4O/8Oavw638X6K+NQnfCgihI+mSJJ0hRBCQ
1lXmqW8MzXHq0XLsmh+PoADEQ8q9oSJ0h9NhcFoMUfi7yhRBNx/+U8UTqqCWyIsJ
LNuD2CC8oltSV3dFlSIRDKI8h8W2XBLxg5a7wncxCyn1emzs+QafbHizOa+fX7Qg
xLBPKqPZBDo4dgnWEvmsZEGkNz8Nsz+Aw2P7cbeDKeqDTwIDAQABo1MwUTAdBgNV
HQ4EFgQU54znG+BiUL+T6SiC2njIteSbuXwwHwYDVR0jBBgwFoAU54znG+BiUL+T
6SiC2njIteSbuXwwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEA
SNgSFWaWq0iR+yERFqUd1Q/VGiRc4ytrL6BpK6jykFPD2PdPZBDhkhvvsMt8CgYA
pSGtxXPLoBTE4FIUa5pVN1B8kEA8vc9UIWQrGNhASCeAmSNMlS4fs5xgG+ISbrTc
dwjbMP9xeX2049qR9EI8Fl5AHMUJJga8RvBWCrmI7CJTalInEc7O67J4bSsGUAM1
eZJbCLmMdDRNkamSjnLoa6LOxs5c5OSR6RyDIp78TQaW+7R+HOJIzyfzFroi3GnE
Sxv5z+9HhPhN7IR608ODKcxxQBJMABBxHP1kcxvGEIYxm+jZLQXOv+H3bJiPMBqX
J8nV2gnPMIAaz0EVKPwmTA==''',
                ]
            },
        chain='''MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow
SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT
GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF
q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8
SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0
Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA
a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj
/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG
CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv
bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k
c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw
VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC
ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz
MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu
Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF
AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo
uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/
wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu
X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG
PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6
KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==''',
        live=1, recreate=True, force=False, bad=False):
    '''
        base: the base directory the test files will be created in. Parent
                directories will not be created.
        le_dir: the directory containing the letsencrypt files.
        domains: dict whose keys are the letsencrypt domain directory to
                create, and whose values are a list of cert.pem contents.
        live: integer N for which certN.pem file to link to as the live
                cert.pem file. Likewise for the other pem files.
        recreate: whether to remove and then re-link the live pem files.
        force: in addition to 'recreate', also overwrite the archive pem files.
        bad: create misconfigured domain directories that will test various
                failures.
    '''

    base_path = Path(base)
    le_path = base_path / le_dir
    le_live_path = le_path / 'live'
    le_archive_path = le_path / 'archive'

    mkdir(base_path)
    mkdir(le_live_path, True)
    mkdir(le_archive_path, True)

    le_domain_path = { d: { 'archive': le_archive_path / d,
                            'live': le_live_path / d } for d in domains }

    for d in le_domain_path:
        mkdir(le_domain_path[d]['archive'])
        mkdir(le_domain_path[d]['live'])

        for pos,data in enumerate(domains[d], 1):
            create(le_domain_path[d]['archive'], 'cert{}.pem'.format(pos),
'''-----BEGIN CERTIFICATE-----
{}
-----END CERTIFICATE-----'''.format(data), force)

            create(le_domain_path[d]['archive'], 'chain{}.pem'.format(pos),
'''-----BEGIN CERTIFICATE-----
{}
-----END CERTIFICATE-----'''.format(chain), force)

            create(le_domain_path[d]['archive'], 'fullchain{}.pem'.format(pos),
'''-----BEGIN CERTIFICATE-----
{}
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
{}
-----END CERTIFICATE-----'''.format(data, chain), force)

            create(le_domain_path[d]['archive'], 'privkey{}.pem'.format(pos),
'''-----BEGIN CERTIFICATE-----
privkey {}
-----END CERTIFICATE-----'''.format(pos), force)

        symlink(le_domain_path[d]['live'], 'cert', d, live, recreate or force)
        symlink(le_domain_path[d]['live'], 'chain', d, live, recreate or force)
        symlink(le_domain_path[d]['live'], 'fullchain', d, live, recreate or force)
        symlink(le_domain_path[d]['live'], 'privkey', d, live, recreate or force)

    if bad:
        # create x.com in archive only
        mkdir(le_archive_path / 'x.com')

        # create y.com in live only
        mkdir(le_live_path / 'y.com')

    return le_path



def exists_and_is_dir(path, symlink=False, must=True):
    '''
                                             must
                              True            |         False
    ---------------+--------------------------+--------------------------+
             True  | path must be a symlink   |                          |
                   | to an existing dir       | path must be an existing |
    symlink  ------+--------------------------+                          +
             False | path must be an existing | dir, symlink or not      |
                   | dir and not a symlink    |                          |
             ------+--------------------------+--------------------------+

    '''
    p = Path(path)
    assert p.exists() and p.is_dir()
    if must:
        if symlink:
            assert p.is_symlink()
        else:
            assert not p.is_symlink()

def exists_and_is_file(path, symlink=False, must=True):
    '''
                                             must
                              True            |         False
    ---------------+--------------------------+--------------------------+
             True  | path must be a symlink   |                          |
                   | to an existing file      | path must be an existing |
    symlink  ------+--------------------------+                          +
             False | path must be an existing | file, symlink or not     |
                   | file and not a symlink   |                          |
             ------+--------------------------+--------------------------+

    '''
    p = Path(path)
    assert p.exists() and p.is_file()
    if must:
        if symlink:
            assert p.is_symlink()
        else:
            assert not p.is_symlink()



def check_state_domain(state, domain):
    if type(domain) is list:
        for d in domain:
            assert d in state.targets
        assert len(state.targets) == len(domain)
    else:
        assert d in state.targets

def check_state_dirs(state, domain,
        dd, san, ddd, led, ld, ldd, ad, add, ll):
    t = state.targets[domain]
    assert t['dane_directory'] == Path(dd)
    assert t['sanitize'] == san
    assert t['dane_domain_directory'] == Path(ddd)
    assert t['letsencrypt_directory'] == Path(led)
    assert t['live_directory'] == Path(ld)
    assert t['live_domain_directory'] == Path(ldd)
    assert t['archive_directory'] == Path(ad)
    assert t['archive_domain_directory'] == Path(add)
    for l in ll:
        assert l in t['live_links']
    assert len(ll) == len(t['live_links'])

def check_state_certs(state, domain, certs):
    assert state.targets[domain]['certs'] == certs

def check_record(state, domain, spec, port, protocol, rdomain=None,
                 data=None, prev_data=None, delete_data=None, published=False,
                 is_up=False, update=None):
    key = '{}._{}._{}.{}'.format(spec, port, protocol, rdomain)
    record = state.targets[domain]['records'][key]
    assert port == record['port']
    assert protocol == record['protocol']
    if rdomain:
        assert rdomain == record['domain']
    else:
        assert domain == record['domain']
    assert spec[0] == record['params']['usage']
    assert spec[1] == record['params']['selector']
    assert spec[2] == record['params']['matching_type']

    assert record['new']['data'] == data
    assert record['new']['published'] == published
    assert record['new']['is_up'] == is_up
    assert record['new']['update'] == update

    assert record['prev']['data'] == prev_data

    if delete_data:
        if record['delete']:
            if record['delete'][delete_data]:
                assert record['delete'][delete_data]['data'] == delete_data
            else:
                assert False
        else:
            assert False
    else:
        if record['delete']:
            assert False

    if data and prev_data:
        assert data != prev_data

def create_exec(base='.alnitak_tests', bin_dir='bin', bin_name='api'):
    base_path = Path(base)
    bin_path = base_path / bin_dir
    api_prog = bin_path / bin_name
    call_data = bin_path / 'call.data'

    mkdir(base_path)
    mkdir(bin_path)

    # api N  - exit with code N
    with open(str(api_prog), 'w') as f:
        f.write(r'''#!/bin/sh
exit_code=0
for i in $@ ; do
    case $i in
        "$ALNITAK_OPERATION:$ALNITAK_ZONE:$ALNITAK_USAGE$ALNITAK_SELECTOR$ALNITAK_MATCHING_TYPE:$ALNITAK_PORT:$ALNITAK_PROTOCOL:$ALNITAK_DOMAIN"::*)
            exit_code=$(echo "$i" | sed 's/.\+:://')
            ;;
        "$ALNITAK_OPERATION"::*)
            exit_code=$(echo "$i" | sed 's/.\+:://')
            ;;
        "$ALNITAK_USAGE$ALNITAK_SELECTOR$ALNITAK_MATCHING_TYPE"::*)
            exit_code=$(echo "$i" | sed 's/.\+:://')
            ;;
    esac
done

echo "$(whoami) x:$exit_code $(env | xargs) " >> $(dirname "$0")/call.data
if test -z "$exit_code" ; then
    exit 0
fi
exit "$exit_code"
''')

    os.chmod(str(api_prog), 0o744)

    return reset_call_data(base=base, bin_dir=bin_dir)

def reset_call_data(base='.alnitak_tests', bin_dir='bin'):
    call_data = Path(base) / bin_dir / 'call.data'
    with open(str(call_data), 'w') as f:
        f.write('')

    return call_data


def read_call_data(base='.alnitak_tests', bin_dir='bin'):
    call_data = Path(base) / bin_dir / 'call.data'
    try:
        with open(str(call_data), 'r') as f:
            return f.read().splitlines()
    except FileNotFoundError:
        return []


def is_in_call_data(call_data, data):
    count = 0
    for l in call_data:
        if type(data) is list:
            for d in data:
                if (d + ' ') not in l:
                    break
            else:
                count += 1
        else:
            if (data + ' ') in l:
                count += 1
    return count

def str_in_list(msg, obj):
    for l in obj:
        if msg in str(l):
            break
    else:
        assert False

def simulate_renew(base='.alnitak_tests', le_dir='etc/le',
                   domains=['a.com', 'b.com', 'c.com'], to=None):
    for d in domains:
        for c in [ 'cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem' ]:
            cert = Path(base) / le_dir / 'live' / d / c

            arx = cert.resolve()

            m = re.match(r'([a-z]+)([0-9])\.pem', arx.name)

            if to:
                new_arx = "{}{}.pem".format(m.group(1), to)
            elif m.group(2) == '1':
                new_arx = "{}2.pem".format(m.group(1))
            elif m.group(2) == '2':
                new_arx = "{}3.pem".format(m.group(1))
            elif m.group(2) == '3':
                new_arx = "{}1.pem".format(m.group(1))
            else:
                new_arx = "{}1.pem".format(m.group(1))

            cert.unlink()
            cert.symlink_to('../../archive/{}/{}'.format(d, new_arx))

def get_data(domain, num, spec):
    '''
    '''
    if spec == '200':
        return '308204923082037aa00302010202100a0141420000015385736a0b85eca708300d06092a864886f70d01010b0500303f31243022060355040a131b4469676974616c205369676e617475726520547275737420436f2e311730150603550403130e44535420526f6f74204341205833301e170d3136303331373136343034365a170d3231303331373136343034365a304a310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074312330210603550403131a4c6574277320456e637279707420417574686f7269747920583330820122300d06092a864886f70d01010105000382010f003082010a02820101009cd30cf05ae52e47b7725d3783b3686330ead735261925e1bdbe35f170922fb7b84b4105aba99e350858ecb12ac468870ba3e375e4e6f3a76271ba7981601fd7919a9ff3d0786771c8690e9591cffee699e9603c48cc7eca4d7712249d471b5aebb9ec1e37001c9cac7ba705eace4aebbd41e53698b9cbfd6d3c9668df232a42900c867467c87fa59ab8526114133f65e98287cbdbfa0e56f68689f3853f9786afb0dc1aef6b0d95167dc42ba065b299043675806bac4af31b9049782fa2964f2a20252904c674c0d031cd8f31389516baa833b843f1b11fc3307fa27931133d2d36f8e3fcf2336ab93931c5afc48d0d1d641633aafa8429b6d40bc0d87dc3930203010001a382017d3082017930120603551d130101ff040830060101ff020100300e0603551d0f0101ff040403020186307f06082b0601050507010104733071303206082b060105050730018626687474703a2f2f697372672e747275737469642e6f6373702e6964656e74727573742e636f6d303b06082b06010505073002862f687474703a2f2f617070732e6964656e74727573742e636f6d2f726f6f74732f647374726f6f74636178332e703763301f0603551d23041830168014c4a7b1a47b2c71fadbe14b9075ffc4156085891030540603551d20044d304b3008060667810c010201303f060b2b0601040182df130101013030302e06082b060105050702011622687474703a2f2f6370732e726f6f742d78312e6c657473656e63727970742e6f7267303c0603551d1f043530333031a02fa02d862b687474703a2f2f63726c2e6964656e74727573742e636f6d2f445354524f4f544341583343524c2e63726c301d0603551d0e04160414a84a6a63047dddbae6d139b7a64565eff3a8eca1300d06092a864886f70d01010b05000382010100dd33d711f3635838dd1815fb0955be7656b97048a56947277bc2240892f15a1f4a1229372474511c6268b8cd957067e5f7a4bc4e2851cd9be8ae879dead8ba5aa1019adcf0dd6a1d6ad83e57239ea61e04629affd705cab71f3fc00a48bc94b0b66562e0c154e5a32aad20c4e9e6bbdcc8f6b5c332a398cc77a8e67965072bcb28fe3a165281ce520c2e5f83e8d50633fb776cce40ea329e1f925c41c1746c5b5d0a5f33cc4d9fac38f02f7b2c629dd9a3916f251b2f90b119463df67e1ba67a87b9a37a6d18fa25a5918715e0f2162f58b0062f2c6826c64b98cdda9f0cf97f90ed434a12444e6f737a28eaa4aa6e7b4c7d87dde0c90244a787afc3345bb442'
    if spec == '201':
        return '25847d668eb4f04fdd40b12b6b0740c567da7d024308eb6c2c96fe41d9de218d'
    if spec == '202':
        return '2e1e12dacb350e69317a7f37d769f46f16f437cf8d392319279c93515e5600baed3d3acd5dc83b673e8c60cf7fba0dce00a4d162a3b966a3ebf72487c376fca0'
    if spec == '210':
        return '30820122300d06092a864886f70d01010105000382010f003082010a02820101009cd30cf05ae52e47b7725d3783b3686330ead735261925e1bdbe35f170922fb7b84b4105aba99e350858ecb12ac468870ba3e375e4e6f3a76271ba7981601fd7919a9ff3d0786771c8690e9591cffee699e9603c48cc7eca4d7712249d471b5aebb9ec1e37001c9cac7ba705eace4aebbd41e53698b9cbfd6d3c9668df232a42900c867467c87fa59ab8526114133f65e98287cbdbfa0e56f68689f3853f9786afb0dc1aef6b0d95167dc42ba065b299043675806bac4af31b9049782fa2964f2a20252904c674c0d031cd8f31389516baa833b843f1b11fc3307fa27931133d2d36f8e3fcf2336ab93931c5afc48d0d1d641633aafa8429b6d40bc0d87dc3930203010001'
    if spec == '211':
        return '60b87575447dcba2a36b7d11ac09fb24a9db406fee12d2cc90180517616e8a18'
    if spec == '212':
        return '774fad8c9a6afc2bdb44faba8390d213ae592fb0d56c5dfab152284e334d7cd6abd05799236e7aa6266edf81907c60404c57ee54c10a3a82fcc2a9146629b140'

    if domain == 'a.com':
        if num == 1:
            if spec == '300':
                return '3082029730820200a003020102020900b667356477fcdeda300d06092a864886f70d01010b05003063310b3009060355040613024742310f300d06035504080c064c6f6e646f6e310f300d06035504070c064c6f6e646f6e3110300e060355040a0c07416c6e6974616b3110300e060355040b0c0774657374696e67310e300c06035504030c05612e636f6d301e170d3139303132343134343234385a170d3139303232333134343234385a3063310b3009060355040613024742310f300d06035504080c064c6f6e646f6e310f300d06035504070c064c6f6e646f6e3110300e060355040a0c07416c6e6974616b3110300e060355040b0c0774657374696e67310e300c06035504030c05612e636f6d30819f300d06092a864886f70d010101050003818d0030818902818100e0383970b39b598eb217e09e767ab86468146b9c24b0136e3054079d878a62211e2e7b95b71ff6790d0a369ea28c84da3699a81a68136c0d41b245d8371fc9cb2ed3c33ed026378d55c4c7ab5b2483370367e373bb639ea200e0f3d4d93b2071f310e519f51fd785407e292c6492883d7e8d93fe55455899ea21cc56a8fa69d50203010001a3533051301d0603551d0e041604148db2c35c49dcb11b4f3f0ed118fb6e5f4af7fbd5301f0603551d230418301680148db2c35c49dcb11b4f3f0ed118fb6e5f4af7fbd5300f0603551d130101ff040530030101ff300d06092a864886f70d01010b050003818100affa35c943532d00100cb30c9a23e4bc8e78604b3cb72abb14021cadf817a404766db786c8d8c8c0ed081b234bd04f80fb8385902e75b7408690e9cd65a8ef21f37e5b096407311e87e28aef58be1224306cbc688affe62b5b8331d1556bc096e76c027eb615163f1b30b4e988fcd42cb61d43ea778be534f00c1990ba8c19b6'
            if spec == '301':
                return '4b6ebf5b27cb8b090a86c19943d9e2d799a3467ef18e8c866c605df46134677a'
            if spec == '302':
                return 'b9bf7c30e2871d5efd022bd35c1b00bbebb54e264bf0ec10ec99d7a2355ac4de2b348be4ff8e2a1add2450fa16aaa74900bc9a2835d3e288edf3a5ccb29ae98e'
            if spec == '310':
                return '30819f300d06092a864886f70d010101050003818d0030818902818100e0383970b39b598eb217e09e767ab86468146b9c24b0136e3054079d878a62211e2e7b95b71ff6790d0a369ea28c84da3699a81a68136c0d41b245d8371fc9cb2ed3c33ed026378d55c4c7ab5b2483370367e373bb639ea200e0f3d4d93b2071f310e519f51fd785407e292c6492883d7e8d93fe55455899ea21cc56a8fa69d50203010001'
            if spec == '311':
                return 'f73e2add0cc95f0890594d203f2829d69f5288feb0431c81bb0336a18054148c'
            if spec == '312':
                return 'b173cfcad24da5defa2f34b6aa1b0d66340b22b7b1541253e86ce9225d8b2478bd0f9fb443cc69f41351562f6b862ac3245c1f27721ca53e3a531df545292501'
        if num == 2:
            if spec == '300':
                return '3082029730820200a0030201020209008c4d1732a8b4b82b300d06092a864886f70d01010b05003063310b3009060355040613024742310f300d06035504080c064c6f6e646f6e310f300d06035504070c064c6f6e646f6e3110300e060355040a0c07416c6e6974616b3110300e060355040b0c0774657374696e67310e300c06035504030c05612e636f6d301e170d3139303132343134343134375a170d3139303232333134343134375a3063310b3009060355040613024742310f300d06035504080c064c6f6e646f6e310f300d06035504070c064c6f6e646f6e3110300e060355040a0c07416c6e6974616b3110300e060355040b0c0774657374696e67310e300c06035504030c05612e636f6d30819f300d06092a864886f70d010101050003818d0030818902818100f2662a786c5aef4ba835c2bf0cea357bd99eddf6f959a4e031806ee0da615eb1768e7f26c96c441f09e50abe51f6a4efdaed1b840f5c465c95ff5ad2ee75688ed07abd131552c21c7d38eba0299146d9c59a0d300680e37f1bc5ebf8e903657a942bb24eaa0732d0d2b831b5fd3efdbcc966d0eca83e061c34671f7d3b597c610203010001a3533051301d0603551d0e04160414422aebd77729dc31f8b3eae2046feccbb367c662301f0603551d23041830168014422aebd77729dc31f8b3eae2046feccbb367c662300f0603551d130101ff040530030101ff300d06092a864886f70d01010b0500038181003ecd748ff831beb6e6797ca8597d2879f0b9ed4d5337cd96f3100f392ec56edeefb06a55fcdd7a7380aa417732993a07943657686effce824a480630958b7ab842ee3816b1305255434038c6b6d4a282717eb9ad970cb99e664f35ce12ab82138eab1fc8cc12dc316a4e1e01471977ac54a6adc1c6de9c051fbfba147bb5e929'
            if spec == '301':
                return '64adbb86d7ef684ead0a68f9ff16cbdc1ae9085bc294c1528c4a463557729c4c'
            if spec == '302':
                return '33d1c6da2f59bbb37562078684bb549276fb8dd06b48ed3da0cd4015e24cde43b018925abbb43bfe5964891855385ffe15cd66c218b2077e5c4191b7f70f3478'
            if spec == '310':
                return '30819f300d06092a864886f70d010101050003818d0030818902818100f2662a786c5aef4ba835c2bf0cea357bd99eddf6f959a4e031806ee0da615eb1768e7f26c96c441f09e50abe51f6a4efdaed1b840f5c465c95ff5ad2ee75688ed07abd131552c21c7d38eba0299146d9c59a0d300680e37f1bc5ebf8e903657a942bb24eaa0732d0d2b831b5fd3efdbcc966d0eca83e061c34671f7d3b597c610203010001'
            if spec == '311':
                return '89d496304d899b10e3320cf3d398be642f57f6a32639d69be22c1ad16e86f113'
            if spec == '312':
                return '9a603785be6226d765b2e2fc9f478cabe7d074e2d32e2af2f7eadcb1d7ed1806faa8bc447667c1f1a9dbcfe6b012da63fd13091d68951863d5699d455bba12ad'
        if num == 3:
            if spec == '300':
                return '3082059c30820384a003020102020900cd58f719fccd49f9300d06092a864886f70d01010b05003063310b3009060355040613024742310f300d06035504080c064c6f6e646f6e310f300d06035504070c064c6f6e646f6e3110300e060355040a0c07416c6e6974616b3110300e060355040b0c0774657374696e67310e300c06035504030c05612e636f6d301e170d3139303132343134303833355a170d3139303232333134303833355a3063310b3009060355040613024742310f300d06035504080c064c6f6e646f6e310f300d06035504070c064c6f6e646f6e3110300e060355040a0c07416c6e6974616b3110300e060355040b0c0774657374696e67310e300c06035504030c05612e636f6d30820222300d06092a864886f70d01010105000382020f003082020a0282020100c116b9d65a7157706f89d049ec987472e330751573028da0480d10ce763e4a05f52f954006af7645b1f8e69510cc24029755279f6feae336213f5eb1209c38d3452b324cbcc48303c698668403d37675e6d1f5e41cc0cf01b04045886b32677597c0be913180aa0a85562578ca4fb6d37fec8887ca380b095202f046e6b054a07a54c7b16589e1ab89e3264f8808f8af3dba51e82fb7729f01e6dfde00585ce481d9adea93c98a95267c9bf51a455b7c62eced1e14df2756022e086a390a2f66f7cf08d87a2ea1265e3fbe0f6efa6ea8e61183a11f61226e51eb24cd0732cdbe740b1878c01db1d8b350643ff5532187c579b005165a5d49ab6c9154761240b4092ef665591c989e8e0ae5da3c5e550b2ca55061d3a1419304847c4a008c42c2f58a752591d7ea6d00cd023f808c05ddda5e3e410e89ba043967bce82d5a006a158dea1891d3482eabc150e670ba6e49f37b3ec603b64f47372184f0430568aff8adfb57919723dcbbb3d6507d4ad3ea747bf5efb7af821c2be892370b33a3bdabf94a87834df93219a3a08e78514a17eb8461718bcce5b36a2cf5e9a7cf964d0e9009c9675b938ab6821b2bee38cef21b9bf4555a6b1092eaffa2b8e5f2e1ef42e169ef0274c8898b218034384894ba21d4ea48ecb04869225f952565ce818e18503d86acbe79ca44d78222dc1f878942c3cdbcd87c30f516a8c93e471502f90203010001a3533051301d0603551d0e04160414ce5b5d64c18ab7e50d7c6452950e528189cd06a0301f0603551d23041830168014ce5b5d64c18ab7e50d7c6452950e528189cd06a0300f0603551d130101ff040530030101ff300d06092a864886f70d01010b050003820201007630eaa8cced9240af693cf9573d4926b5c6a3a1026323b1af0e564907d66fb5978f0d20dc2f709e425077bf467e60ac5cdab4dcb55e088be33843e0b988652d9484a21fd7a3698566010c0ae0d6eb7ef3f6a05688d49de353898224c8be7e70f64aff9f0285d2b27aa6602927ddce18883f59cccec8a08ad393b5793f7c2c46a61b9cbbb3a3a66bbeb693cac0d2e37a781e2c23a19ef8d8f1773de165601976363a60899d941d06f2bc640fcf0ed91be98410594e8359919742194b9a62a9647baa104fc56f6fb4981e2f2bdf5e020771afa32fedccf75824ff3f58a43fa1c0e90265d454747c38e26de25b8c931a4633ebf6855ffda1a84bc4cfd0594089f555340a22799b579dc0fdf5bb13fcbb659cdf655e6924fe98b9607230459ad6b48827dfbe0c95a36ea076a7980e85812aad03097536ff3115b7389406eae156807813e5b349d15231d2e799c668f64484c23827ff7150c0d19fec0e3191d78ac1e01cf53fe8c7e238d0e86d53712f813e874fb8eddef125f58d66614f9bff0d937e89d91d267af6351112f0e7eb0b3c69f02671822d21b998bb0d050b52bd24da8b1615fd3d6a91cb280e825312791c947b245c363dacdea226f84c955e9c751f10598147def73938fac82877fed71fb1cca3953e956846641e7f15ddfeba3f8072e864ef3d621ce68df6244208dbf5a91b16f18b007317f48b06a0c72a1d6199'
            if spec == '301':
                return '67f76c1b4945cb0eead61b9b5872624204a69e6f162c28e18f4c8f0a0cd9e879'
            if spec == '302':
                return '18a1533c41e47db5f6f7c316e782f2101e8367f50dd01532bfb94719d015148f6b43367cd2e8f68ee7d0500699f1823dd12b7ecb2b7390ab14a16ffb94329188'
            if spec == '310':
                return '30820222300d06092a864886f70d01010105000382020f003082020a0282020100c116b9d65a7157706f89d049ec987472e330751573028da0480d10ce763e4a05f52f954006af7645b1f8e69510cc24029755279f6feae336213f5eb1209c38d3452b324cbcc48303c698668403d37675e6d1f5e41cc0cf01b04045886b32677597c0be913180aa0a85562578ca4fb6d37fec8887ca380b095202f046e6b054a07a54c7b16589e1ab89e3264f8808f8af3dba51e82fb7729f01e6dfde00585ce481d9adea93c98a95267c9bf51a455b7c62eced1e14df2756022e086a390a2f66f7cf08d87a2ea1265e3fbe0f6efa6ea8e61183a11f61226e51eb24cd0732cdbe740b1878c01db1d8b350643ff5532187c579b005165a5d49ab6c9154761240b4092ef665591c989e8e0ae5da3c5e550b2ca55061d3a1419304847c4a008c42c2f58a752591d7ea6d00cd023f808c05ddda5e3e410e89ba043967bce82d5a006a158dea1891d3482eabc150e670ba6e49f37b3ec603b64f47372184f0430568aff8adfb57919723dcbbb3d6507d4ad3ea747bf5efb7af821c2be892370b33a3bdabf94a87834df93219a3a08e78514a17eb8461718bcce5b36a2cf5e9a7cf964d0e9009c9675b938ab6821b2bee38cef21b9bf4555a6b1092eaffa2b8e5f2e1ef42e169ef0274c8898b218034384894ba21d4ea48ecb04869225f952565ce818e18503d86acbe79ca44d78222dc1f878942c3cdbcd87c30f516a8c93e471502f90203010001'
            if spec == '311':
                return '0da25074bc07d104653c29dd7ff993b421436cd34ccec15503741d50d4b0df3e'
            if spec == '312':
                return '0d25edeec3bb81f82f84842854db3f31f8b97236517e70abb36215e5a2ef3d2b73026722e0b6d9222f1cad1b600fa7ed24eedb47467659fc48cbb92b9594dff5'
    if domain == 'b.com':
        if num == 1:
            if spec == '300':
                return '3082029730820200a0030201020209008cd9e96d57245c82300d06092a864886f70d01010b05003063310b3009060355040613024742310f300d06035504080c064c6f6e646f6e310f300d06035504070c064c6f6e646f6e3110300e060355040a0c07416c6e6974616b3110300e060355040b0c0774657374696e67310e300c06035504030c05622e636f6d301e170d3139303132343134343535395a170d3139303232333134343535395a3063310b3009060355040613024742310f300d06035504080c064c6f6e646f6e310f300d06035504070c064c6f6e646f6e3110300e060355040a0c07416c6e6974616b3110300e060355040b0c0774657374696e67310e300c06035504030c05622e636f6d30819f300d06092a864886f70d010101050003818d0030818902818100ccce5f013a28c54116fc810391d102cbaf58c2dd6cbb41208e1449e6f8b6541fa884046eb34a203ada3e33bc40d1a7530682aabeb141c106bea56965e4474f24b1077abbb7d54e624b603f2c25cfb03aeef25093b1f4b249b86a9447c5c9e90d09ea8d37eba601517dccb38f0e3d42ed363a0219c509772ab085b6fab1f48a610203010001a3533051301d0603551d0e04160414f440a4866373f5fd7ce0b20c7aebb5f30af5d19f301f0603551d23041830168014f440a4866373f5fd7ce0b20c7aebb5f30af5d19f300f0603551d130101ff040530030101ff300d06092a864886f70d01010b05000381810080e6278a6385de7095e1866b71eca28f541b1ef5a4e69581caa165b0a536fe7c3b8e5f23b892155a1199915f3b6dea2360476b20c1431501956300255bd7a7bc8b78271854ba5231b37e16b1f29015cddfd79e38a57a3d0e6bcd3484a50eb31012fb961f4745a6116680daee537d7df8fbe576972ac2aa38b8da72ef6671ff9d'
            if spec == '301':
                return 'e448c386abce2a8f5962b163720c6651738a12e5bb39123237e3b29913d802ea'
            if spec == '302':
                return '92c057cfe645e6c176f0e944bedec49d02a9d295493510b5c7cc01bfe6370d2dd215f672c4e6f692f02fc5642e6b5154c877438820cb5f53d330a524315fc035'
            if spec == '310':
                return '30819f300d06092a864886f70d010101050003818d0030818902818100ccce5f013a28c54116fc810391d102cbaf58c2dd6cbb41208e1449e6f8b6541fa884046eb34a203ada3e33bc40d1a7530682aabeb141c106bea56965e4474f24b1077abbb7d54e624b603f2c25cfb03aeef25093b1f4b249b86a9447c5c9e90d09ea8d37eba601517dccb38f0e3d42ed363a0219c509772ab085b6fab1f48a610203010001'
            if spec == '311':
                return 'e5f88030480e359c17a33d2f02c42033b6eb5b482f182930087bb6fa8c701805'
            if spec == '312':
                return 'e5024953edaccf482c438f2dcd1cee98b31094fd9f959c3dc071d6027cb58eec94cd8c9389915d2096b19469141cb29cbd63bbcdde03d8ceaa04f20c523149e3'
        if num == 2:
            if spec == '300':
                return '3082029730820200a003020102020900926f759f7d9f6122300d06092a864886f70d01010b05003063310b3009060355040613024742310f300d06035504080c064c6f6e646f6e310f300d06035504070c064c6f6e646f6e3110300e060355040a0c07416c6e6974616b3110300e060355040b0c0774657374696e67310e300c06035504030c05622e636f6d301e170d3139303132343134343632315a170d3139303232333134343632315a3063310b3009060355040613024742310f300d06035504080c064c6f6e646f6e310f300d06035504070c064c6f6e646f6e3110300e060355040a0c07416c6e6974616b3110300e060355040b0c0774657374696e67310e300c06035504030c05622e636f6d30819f300d06092a864886f70d010101050003818d0030818902818100b937e23244598f39f0517dfcf38a598b5362d484e1bc83a799fa4e2a954eb3fa0b681f57eedfc9edee2d0cdbfdc2b98901a17290c2089e74fe6f21376c71480b9029552d927661a079b79b78dbdbbba9910206cf8955128b57fedf45f18b45d0a222c5ce60c31e7a49fac96fdc55823958f8b2b0586cf77745c8805502a90f3f0203010001a3533051301d0603551d0e0416041422f645925207c0d645788527b39fd20430c5a0c6301f0603551d2304183016801422f645925207c0d645788527b39fd20430c5a0c6300f0603551d130101ff040530030101ff300d06092a864886f70d01010b05000381810014aa34d60711aeed625391abf6b04d1fbb62b104bb867ab4adf124123b060286337f6ca5e5cacff01c71abae1678c29ffbf0b50acc28f7541e0fcd4f3bf21e8911482c75b934a14bcce13b9972dbfa0dd5d51069c8add4512dbee6deecbaefb39e8e8333538bfe1a768a19d589e00ecf173d3d56fd6bb129de8a791d54bb21de'
            if spec == '301':
                return '62ff6fe596af9cd6a50aa3ea213d9ddda51c117d1d415a2fbfb858101ef8d532'
            if spec == '302':
                return 'f8f43871414fef37ea5bea19a1cd57e8f7a528276a4a6934cfe89bd44aaf22c6d1f0d81f9934fc5534bbea80cc281747aa4704688f54e8b0cac3841732a01726'
            if spec == '310':
                return '30819f300d06092a864886f70d010101050003818d0030818902818100b937e23244598f39f0517dfcf38a598b5362d484e1bc83a799fa4e2a954eb3fa0b681f57eedfc9edee2d0cdbfdc2b98901a17290c2089e74fe6f21376c71480b9029552d927661a079b79b78dbdbbba9910206cf8955128b57fedf45f18b45d0a222c5ce60c31e7a49fac96fdc55823958f8b2b0586cf77745c8805502a90f3f0203010001'
            if spec == '311':
                return '9be00418751c2889dc6688d5e88b52da8c1696add47b7073beda4c3bb0fad469'
            if spec == '312':
                return '549477faac78a5892b351077051ed8b7eaac7457f079fa130835fb72d33baee4e552f6668526a66f680001589500d768a9adaf1114c041a2517b7cf9d1791c90'
        if num == 3:
            if spec == '300':
                return '3082039c30820284a003020102020900b6151540dee2bfb7300d06092a864886f70d01010b05003063310b3009060355040613024742310f300d06035504080c064c6f6e646f6e310f300d06035504070c064c6f6e646f6e3110300e060355040a0c07416c6e6974616b3110300e060355040b0c0774657374696e67310e300c06035504030c05622e636f6d301e170d3139303132343134343335365a170d3139303232333134343335365a3063310b3009060355040613024742310f300d06035504080c064c6f6e646f6e310f300d06035504070c064c6f6e646f6e3110300e060355040a0c07416c6e6974616b3110300e060355040b0c0774657374696e67310e300c06035504030c05622e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100d309b11f5b942c715b6af60ff14adc0f3f446c2d8366eb2ea02fa21fcde2f5ad85fb203645e217eaf1d7a686c37f687aed2e4217ce5e71aec1e6f8869f08a5e4871bc6489e59e2bff7c12d8294fae33e8a536b4f14d2f735e46ec9a2b087a025c291e413f2426ebab3265aa56aaac13a4f8cdd4b956cb2e51551cd75721301fcc57d65566527dd452937a4c493da5e7b63553ad918e2246ad17a4c470adceddd44661a1b369d1105ab70a3c80b7043afa76ec04ad73703cc3edd4c5ec542e73a2e05677cdf752b3b5154ce04111bca0c87f65f025b439c2d5f68fb65529efa4b9dcb84619ca5b212a8886293203fc9a00593917a6e7db8b8ee88a14a33ee40050203010001a3533051301d0603551d0e041604140563063cb36ba24363b942e187f99fbbf8b11891301f0603551d230418301680140563063cb36ba24363b942e187f99fbbf8b11891300f0603551d130101ff040530030101ff300d06092a864886f70d01010b05000382010100a357330469905bb9abd8b568930736253075107ff61797c5b31ab93215c36bb08aa230c68cde32ff3c19b865bbfef93761232ccb1fdf58fdc73057bbde06aa31753003171334f5efe4244d03a0633f4b91e85cf4e3eea5f6cded08ca3396341372871c24dcf381d49c6a82c08b67cc4a82e7da807f12f8e1d3f9ed92d22d4eaa51b9578d1428ffc2c29086cc7da946461221147a924e7aa1cf831c769c8f0a40931790882f8239185a52192723e908d5ded0146ea5e335aba49bb60c3668bdc16a23a7bf9db3d31d5fe13cd11ad4a6df996db518fe196d08437fbc50228f67741f8c9473150c41ae3f4fe6b1e00cec98f320a37acc634db141418fa188a7576d'
            if spec == '301':
                return 'b51537af4a092f3de9a5821bc770228a4c942e3d0ff71cf347cd17c858c1a00c'
            if spec == '302':
                return '1db9c27fca8cd5d6b7568badac25477dcdb4418fb544bb8873c3d79f6ce2234c7ddaa23a1916e4119eefde6843330ed18b8b3b181aea526748ad5e5c99a36806'
            if spec == '310':
                return '30820122300d06092a864886f70d01010105000382010f003082010a0282010100d309b11f5b942c715b6af60ff14adc0f3f446c2d8366eb2ea02fa21fcde2f5ad85fb203645e217eaf1d7a686c37f687aed2e4217ce5e71aec1e6f8869f08a5e4871bc6489e59e2bff7c12d8294fae33e8a536b4f14d2f735e46ec9a2b087a025c291e413f2426ebab3265aa56aaac13a4f8cdd4b956cb2e51551cd75721301fcc57d65566527dd452937a4c493da5e7b63553ad918e2246ad17a4c470adceddd44661a1b369d1105ab70a3c80b7043afa76ec04ad73703cc3edd4c5ec542e73a2e05677cdf752b3b5154ce04111bca0c87f65f025b439c2d5f68fb65529efa4b9dcb84619ca5b212a8886293203fc9a00593917a6e7db8b8ee88a14a33ee40050203010001'
            if spec == '311':
                return '20a8da331b07bae5b4aa717d63c3734d48ecfadb7699a7fdce256afbd315903b'
            if spec == '312':
                return '83267dab049bb6f7a04da73b6f63c3de0ae146f3d28cd2697e1bb15c94b5a419dae9268b2143141fc09b4029a937e385ab49262e7962ecc96044d44200de63e6'
    if domain == 'c.com':
        if num == 1:
            if spec == '300':
                return '3082029730820200a003020102020900fc41cb412f02716c300d06092a864886f70d01010b05003063310b3009060355040613024742310f300d06035504080c064c6f6e646f6e310f300d06035504070c064c6f6e646f6e3110300e060355040a0c07416c6e6974616b3110300e060355040b0c0774657374696e67310e300c06035504030c05632e636f6d301e170d3139303132343134343533365a170d3139303232333134343533365a3063310b3009060355040613024742310f300d06035504080c064c6f6e646f6e310f300d06035504070c064c6f6e646f6e3110300e060355040a0c07416c6e6974616b3110300e060355040b0c0774657374696e67310e300c06035504030c05632e636f6d30819f300d06092a864886f70d010101050003818d0030818902818100b27884e1ed6c5ff04b574c0c77ba0411a2e5bfe5c68177782f164c9cec5ff3d417299ab0b882205a9c9ae3393c53ccea9844d71f4453125c8e448e12c011a558e723777712e1dfc684142598618502984fb9e20239bd04255765db8d83453127a2a3974150e9f1fc7f5e71f29aa95925a4e576ed227e72e111ac60072f87b4670203010001a3533051301d0603551d0e04160414a8f680c34724df4b6a189b20d6d06c266a8dfa7e301f0603551d23041830168014a8f680c34724df4b6a189b20d6d06c266a8dfa7e300f0603551d130101ff040530030101ff300d06092a864886f70d01010b0500038181000ed1e0d9f0be2d8459e4ffc45b41ec52dd1981abded65f57526295620851b29d7bb15a4839bf7359d5cd4a5c8645ef9ed14842602a327cba313bbf9e7b832d92795cec7687f21b6dc32bb1bd17ae94477e3861098aa9d3c71ddf23ba59baa562746704d2d1afa94a61f58d694e631d404232847b4449b679ea6c1777178be435'
            if spec == '301':
                return '19b8a37e7217b04fe2a06462b01058ef17673cde32f98c314688f2f041edffc1'
            if spec == '302':
                return 'e9a4602874fbac163ec7f6691b355e8bf48395f9ff5ad507a1ea5b6baaf2f0d7e6bce297f6cc3374b6cda984acd2831bc61ab9b94948980fae50faae5a19f174'
            if spec == '310':
                return '30819f300d06092a864886f70d010101050003818d0030818902818100b27884e1ed6c5ff04b574c0c77ba0411a2e5bfe5c68177782f164c9cec5ff3d417299ab0b882205a9c9ae3393c53ccea9844d71f4453125c8e448e12c011a558e723777712e1dfc684142598618502984fb9e20239bd04255765db8d83453127a2a3974150e9f1fc7f5e71f29aa95925a4e576ed227e72e111ac60072f87b4670203010001'
            if spec == '311':
                return 'b9d0f21a2c0eab9254bdd530c503ad3aa33354bb147d6d054e2c70a1b208e938'
            if spec == '312':
                return '2fa354783d4fe1b926f1976e8169deb75e1ca41ef6234ddfead41d0b9854162b0d54df335060852436f023444c40af32575e58511a0b31a137199f5737589dce'
        if num == 2:
            if spec == '300':
                return '3082029730820200a00302010202090080ba59108fb6ef0b300d06092a864886f70d01010b05003063310b3009060355040613024742310f300d06035504080c064c6f6e646f6e310f300d06035504070c064c6f6e646f6e3110300e060355040a0c07416c6e6974616b3110300e060355040b0c0774657374696e67310e300c06035504030c05632e636f6d301e170d3139303132343134343531315a170d3139303232333134343531315a3063310b3009060355040613024742310f300d06035504080c064c6f6e646f6e310f300d06035504070c064c6f6e646f6e3110300e060355040a0c07416c6e6974616b3110300e060355040b0c0774657374696e67310e300c06035504030c05632e636f6d30819f300d06092a864886f70d010101050003818d0030818902818100b0d99b386488027cb28535c33a9bd61a53e68991639a7161fb8e09441897a67cb974cf8119a5d259321bae8c3178a1e58f02319fde2c531f5bb161592292fbeddcdadd1f8ad042658eaa0610e5932634d32ea65aced113698589fec0bdc2abc46fe1eaa3f4b9dd21faf12ab8061ee8d4a358a0db967385daa0991e346e38ce9d0203010001a3533051301d0603551d0e041604143952d825cc106e62545ffe998e267dcdc2978628301f0603551d230418301680143952d825cc106e62545ffe998e267dcdc2978628300f0603551d130101ff040530030101ff300d06092a864886f70d01010b0500038181009b0687cb8be7cecc3d22c23ad361a2f8a34829e14d87f22df937fd7e2aee66254bf9b56344ca97968ddb9b864d9bc4147f436ebf376fae00247cefedc20557842724df15d42dae01e3139407367dc9bb5688da5663a546ee84886f2b3338f29828a8930c2c35a0b4afa1c676f99d65b4d6185be89897789582c7791eab1b74d0'
            if spec == '301':
                return '06a7e55b1525c14f1536b1fa56bd32c4a8fa019893192a781dc989bf41814afc'
            if spec == '302':
                return 'fa297515255d44b3f97327e47f4f1b07c363f204265b7dbbd41c2d3073c3def5c2f565f4c3f3046bf8cf2d602b7e0f911a15b5f6d815b8281d2288e3de857aa5'
            if spec == '310':
                return '30819f300d06092a864886f70d010101050003818d0030818902818100b0d99b386488027cb28535c33a9bd61a53e68991639a7161fb8e09441897a67cb974cf8119a5d259321bae8c3178a1e58f02319fde2c531f5bb161592292fbeddcdadd1f8ad042658eaa0610e5932634d32ea65aced113698589fec0bdc2abc46fe1eaa3f4b9dd21faf12ab8061ee8d4a358a0db967385daa0991e346e38ce9d0203010001'
            if spec == '311':
                return '8260378e9c69fcbd165af31e12c915c41fe013e892a847a88f4f9e893ff57f24'
            if spec == '312':
                return 'd7ce961fa365f74512f01ae6c766ac9992f886363cea48bbb8d99a1848f07d8556cd99e9ab1b9b3a5c31db75d1122e7b9aebd6b131e46944f2161a5feac85fc0'
        if num == 3:
            if spec == '300':
                return '3082039c30820284a0030201020209009aec6226ce0f0378300d06092a864886f70d01010b05003063310b3009060355040613024742310f300d06035504080c064c6f6e646f6e310f300d06035504070c064c6f6e646f6e3110300e060355040a0c07416c6e6974616b3110300e060355040b0c0774657374696e67310e300c06035504030c05632e636f6d301e170d3139303132343134343431365a170d3139303232333134343431365a3063310b3009060355040613024742310f300d06035504080c064c6f6e646f6e310f300d06035504070c064c6f6e646f6e3110300e060355040a0c07416c6e6974616b3110300e060355040b0c0774657374696e67310e300c06035504030c05632e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100adf31ac70d9a7db5b4974d303f72ebe8af93eba09eb129afe594e8252035a24f5c3a7fb80e9d7de72f330993c78b313775ac3862682f9eff60fd3b7a34656c39a23e6f586be57194cd4c8e3992bf7df70eba8c30efe49e75b17de29550f9c0b9ad4035c783bff0e6afc3adfc5fa2be3509df0a08a123e992249d21441090d655e6a96f0ccd71ead172ec9a1f8fa000c443cabda1227487d361705a0c51f8bbca1441371ffe53c513aaa096c88b092cdb83d820bca25b525777459522110ca23c87c5b65c12f18396bbc277310b29f57a6cecf9069f6c78b339af9f5fb420c4b04f2aa3d9043a387609d612f9ac6441a4373f0db33f80c363fb71b78329ea834f0203010001a3533051301d0603551d0e04160414e78ce71be06250bf93e92882da78c8b5e49bb97c301f0603551d23041830168014e78ce71be06250bf93e92882da78c8b5e49bb97c300f0603551d130101ff040530030101ff300d06092a864886f70d01010b0500038201010048d812156696ab4891fb211116a51dd50fd51a245ce32b6b2fa0692ba8f29053c3d8f74f6410e1921befb0cb7c0a0600a521adc573cba014c4e052146b9a5537507c90403cbdcf5421642b18d84048278099234c952e1fb39c601be2126eb4dc7708db30ff71797db4e3da91f4423c165e401cc5092606bc46f0560ab988ec22536a522711ceceebb2786d2b0650033579925b08b98c74344d91a9928e72e86ba2cec6ce5ce4e491e91c83229efc4d0696fbb47e1ce248cf27f316ba22dc69c44b1bf9cfef4784f84dec847ad3c38329cc7140124c0010711cfd64731bc61086319be8d92d05cebfe1f76c988f301a9727c9d5da09cf30801acf411528fc264c'
            if spec == '301':
                return 'a33dd4789fa25280d9bbeba11e15957c917347f863d79b4e75011b7413c9f49e'
            if spec == '302':
                return '7c6609b5ca9e76cd38983b6094b4cbfcbfc69f8ac1c664ac1ebc6ec2ca51ad120b5a6ddaab856d471c2f8719453089b83dfb12096f02da683372e3562ec3cbfc'
            if spec == '310':
                return '30820122300d06092a864886f70d01010105000382010f003082010a0282010100adf31ac70d9a7db5b4974d303f72ebe8af93eba09eb129afe594e8252035a24f5c3a7fb80e9d7de72f330993c78b313775ac3862682f9eff60fd3b7a34656c39a23e6f586be57194cd4c8e3992bf7df70eba8c30efe49e75b17de29550f9c0b9ad4035c783bff0e6afc3adfc5fa2be3509df0a08a123e992249d21441090d655e6a96f0ccd71ead172ec9a1f8fa000c443cabda1227487d361705a0c51f8bbca1441371ffe53c513aaa096c88b092cdb83d820bca25b525777459522110ca23c87c5b65c12f18396bbc277310b29f57a6cecf9069f6c78b339af9f5fb420c4b04f2aa3d9043a387609d612f9ac6441a4373f0db33f80c363fb71b78329ea834f0203010001'
            if spec == '311':
                return 'b4e5e7da9a76ab60fee17a736beaaf21090038f76468e9d46e853de0259d22ad'
            if spec == '312':
                return '3596ab9e1505a1c7a8725dffe6c87d672a4004ce0db3152a88420fa0ad82054d85e35f151b03f7382f21471571434bdc54a2a9db8ab13b53ca10b40c6324fc04'
    return 'nodata'


def debug_cut_paths(p, cut):
    if not p:
        return p
    if not cut:
        return p
    if len(p.parents) > 4:
        return "...{}".format( p.relative_to(list(p.parents)[4]) )
    else:
        return p

def debug_print(state, pcut=False, dcut=False):
    print('~~~~~~ state ~~~~~~~~~~~~~~~~~~~~~')
    print()
    print('renewed domains: {}'.format(state.renewed_domains))
    print('call: {}'.format(state.call))
    print('log level: {}'.format(state.log_level))
    print('testing mode: {}'.format(state.testing_mode))
    for d in state.targets:
        target = state.targets[d]
        print()
        print(d)
        print('-'*len(d))
        print('  dane directory:           {}'.format(debug_cut_paths(target['dane_directory'], pcut)))
        print('      + sanitize: {}'.format(str(target['sanitize'])))
        print('  dane domain directory:    {}'.format(debug_cut_paths(target['dane_domain_directory'], pcut)))
        print('  letsencrypt directory:    {}'.format(debug_cut_paths(target['letsencrypt_directory'], pcut)))
        print('  live directory:           {}'.format(debug_cut_paths(target['live_directory'], pcut)))
        print('  live domain directory:    {}'.format(debug_cut_paths(target['live_domain_directory'], pcut)))
        print('  archive directory:        {}'.format(debug_cut_paths(target['archive_directory'], pcut)))
        print('  archive domain directory: {}'.format(debug_cut_paths(target['archive_domain_directory'], pcut)))
        print('  live links: {}'.format(str(target['live_links'])))
        print('  ttl: {}'.format(str(target['ttl'])))
        print('  tainted: {}'.format(str(target['tainted'])))
        print('  progress: {}'.format(str(target['progress'])))
        print('  certs:')
        for c in target['certs']:
            print('    {}'.format(str(c)))
            print('        + dane:    {}'.format(debug_cut_paths(target['certs'][c]['dane'], pcut)))
            print('        + live:    {}'.format(debug_cut_paths(target['certs'][c]['live'], pcut)))
            print('        + archive: {}'.format(debug_cut_paths(target['certs'][c]['archive'], pcut)))
            print('        + renew:   {}'.format(debug_cut_paths(target['certs'][c]['renew'], pcut)))
        for r in target['records']:
            print('  records:')
            print('    {}'.format(r))
            print('      usage: {}  selector: {}  matching_type: {}'.format(str(target['records'][r]['params']['usage']), str(target['records'][r]['params']['selector']), str(target['records'][r]['params']['matching_type'])))
            print('      port: {}  protocol: {}  domain: {}'.format(str(target['records'][r]['port']), str(target['records'][r]['protocol']), str(target['records'][r]['domain'])))
            print('      delete:')
            if target['records'][r]['delete']:
                for dr in target['records'][r]['delete']:
                    delrec = target['records'][r]['delete'][dr]
                    if delrec['data']:
                        if dcut:
                            print('          data: {}...{}'.format(str(delrec['data'][:10]), str(delrec['data'][-10:])))
                        else:
                            print('          data: {}'.format(delrec['data']))
                    else:
                        print('          data: {}'.format(delrec['data']))
                    print('          time: {}'.format(str(delrec['time'])))
            else:
                print('          None')
            print('      new:')
            if target['records'][r]['new']['data']:
                if dcut:
                    print('          data: {}...{}'.format(str(target['records'][r]['new']['data'][:10]), str(target['records'][r]['new']['data'][-10:])))
                else:
                    print('          data: {}'.format(target['records'][r]['new']['data']))
            else:
                print('          data: {}'.format(target['records'][r]['new']['data']))
            print('          published: {}'.format(str(target['records'][r]['new']['published'])))
            print('          is_up: {}'.format(str(target['records'][r]['new']['is_up'])))
            print('          update: {}'.format(str(target['records'][r]['new']['update'])))
            print('          time: {}'.format(str(target['records'][r]['new']['time'])))
            print('      prev:')
            if target['records'][r]['prev']['data']:
                if dcut:
                    print('          data: {}...{}'.format(str(target['records'][r]['prev']['data'][:10]), str(target['records'][r]['prev']['data'][-10:])))
                else:
                    print('          data: {}'.format(target['records'][r]['prev']['data']))
            else:
                print('          data: {}'.format(target['records'][r]['prev']['data']))
            print('          time: {}'.format(str(target['records'][r]['prev']['time'])))
            if target['api']['type'] == 'exec':
                print('        api:')
                print('            type: exec')
                print('            command: {}'.format(str(target['api']['command'])))
                print('            uid: {}  gid: {}'.format(str(target['api']['uid']), str(target['api']['gid'])))
            elif target['api']['type'] == 'cloudflare':
                print('        api:')
                print('            api: cloudflare')
                print('            version: {}'.format(str(target['api']['version'])))
                print('            zone: {}'.format(str(target['api']['zone'])))
                print('            email: {}'.format(str(target['api']['email'])))
                print('            key: {}'.format(str(target['api']['key'])))
            else:
                print('        <unknown> {}'.format(target['api']))

def set_update_api(state, domain, command):
    state.targets[domain]['api']['command'] = command
