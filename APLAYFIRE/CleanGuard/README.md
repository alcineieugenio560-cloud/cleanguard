# APLAYFIRE
Limpador e verificador de segurança para Android.

## Como gerar o APK
1. Crie um repositório no GitHub e envie estes arquivos (git push).
2. Vá em **Actions > Build APK** (roda sozinho a cada push).
3. Ao terminar, baixe o APK em **Artifacts > CleanGuard-apk**.
4. Instale no celular (permita "fontes desconhecidas").

## Recursos
- Status de RAM/armazenamento
- Verificação de apps: instalação fora de loja, permissões perigosas, combinações típicas de trojans e hashes SHA-256 na `assets/blocklist.txt`
- Busca e remoção de arquivos inúteis (.tmp, .log, .bak, vazios) + cache próprio
