
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

def setup_exec(base='.alnitak_tests', bin_dir='bin', bin_name='api'):
    base_path = Path(base)
    bin_path = base_path / bin_dir
    api_prog = bin_path / bin_name

    mkdir(base_path)
    mkdir(bin_path)

    # api N  - exit with code N
    with open(str(api_prog), 'w') as f:
        f.write(r'''#!/bin/sh
if expr match "$1" '^[0-9]\+$' >/dev/null 2>&1; then
    exit "$1"
else
    exit 0
fi
''')

    os.chmod(str(api_prog), 0o744)


def simulate_renew(base='.alnitak_tests', le_dir='etc/le',
                   domains=['a.com', 'b.com', 'c.com'], to=None):
    for d in domains:
        for c in [ 'cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem' ]:
            cert = path(base) / le_dir / 'live' / d / c

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
            cert.symlink_to('../../{}'.format(new_arx))



