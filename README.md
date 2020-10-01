# Check Point Connectivity Checker
Diese Script testet die Connectivity zu diversen Cloud Diensten, die ein Check Point Management bzw. ein Check Point Gateway für seine Funktion benötigt. Die getesteten Diensten stammen aus dem SK83520.

## Features

Checkt die Verbindung zu den wichtigsten Check Point Cloud Services

## Usage

Entweder mittels `git clone https://172.27.46.15/thomas/checkpoint-check-connectivity.git` das Repo klonen und die Datei auf den Check Point Host kopieren. Der direkte Download kann über https://172.27.46.15/thomas/checkpoint-check-connectivity/raw/master/check_connectivity_to_cp_sk83520.sh erfolgen. Die Datei mit `chmod +x check_connectivity_to_cp_sk83520.sh`ausführbar machen.

Das Script läuft auf Check Point Management Servern und auf Gateways.

```
./check_connectivity_to_cp_sk83520.sh
```

## Fehlerreporting

Fehler bitte hier unter Issues reporten.