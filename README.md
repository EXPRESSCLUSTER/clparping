# clparping

This command can be used instead of **IP monitor resource** in the same broad cast domain.

clparping sends ARP request packet periodically to **the same broad cast domain**.
If clparping receives ARP reply from target IP within a certain period, the target IP will be healthy.
If clparping does not receive ARP reply within a certain period, the target IP will be down and clparping regards it as error.

## How to install clparping on EXPRESSXCLUSTER cluster
1. Download [clparping](https://github.com/EXPRESSCLUSTER/clparping/releases).
1. Copy clparping to `/opt/nec/clusterpro/bin` on EXPRESSCLUSTER cluster nodes.
1. Grant execute permission of clparping to root user.
    ```
    > chmod 744 /opt/nec/clusterpro/bin/clparping
    ```
1. Create custom monitor resource on Cluster Manager.
    - Use [this script](src/genw.sh) for genw.sh.
    - Specify server name and target IP address in genw.sh
        - You can target IP address for each cluster nodes.
            ```
            server1=(cent70-1 192.168.137.80)
            server2=(cent70-2 192.168.137.81)
            server3=
            server4=
            server5=
            .
            .
            ```

## Command option
```
clparping <DEST_IP> [-q] [-w timeout]
```
- `DEST_IP`
    - Used to specify a monitoring target IP address.
    - IP address must contain three periods and four octets.
        - e.g. 192.168.0.1
- `-q`
    - Used to suppress warning messages on Cluster WebUI.
    - This option can be omitted.
- `-w timeout`
    - Used to specify the time for waiting for ARP reply.
    - This option can be omitted. If you omit this option, the timeout value is set as 3 seconds.