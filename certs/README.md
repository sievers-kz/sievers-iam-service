# Certs/
## Что в папке?
### Сюда кладут private.pem & public.pem RSA-ключи

## Правила
### Нельзя коммитить ключи в Git и отправлять кому либо

## Как создать?
### 1. Сгенерируйте приватный ключ с помощью консольной команды:
```
openssl genrsa -out certs/private.pem 2048
```
### 2. Сгенерируйте публичный ключ:
```
openssl rsa -in certs/private.pem -pubout -out certs/public.pem
```
### 3. Установите права через `chmod`:
```
chmod 600 certs/private.pem
```
