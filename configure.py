"""Create local secrets once; never overwrite existing keys."""
from pathlib import Path
import secrets
from cryptography.fernet import Fernet

path = Path(__file__).with_name('.env')
if path.exists():
    print('.env already exists; retained')
else:
    path.write_text(f'SECRET_KEY={secrets.token_hex(32)}\nFIELD_KEY={Fernet.generate_key().decode()}\nPOSTGRES_PASSWORD={secrets.token_hex(24)}\nDATABASE_URL=sqlite:///school.db\nCOOKIE_SECURE=0\n', encoding='utf-8')
    print('Created .env. Keep a secure backup of FIELD_KEY.')
