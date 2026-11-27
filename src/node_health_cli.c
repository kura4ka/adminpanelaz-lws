#include "node_transport.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fputs("usage: adminpanelaz-node-health http[s]://host[:port]\n"
              "Read X-Node-Key from APAZ_NODE_KEY. Optional PEM paths: APAZ_NODE_CA, APAZ_NODE_CERT, APAZ_NODE_PRIVATE_KEY.\n",
              stderr);
        return 2;
    }
    if (!node_transport_init()) {
        fputs("Cannot initialize node transport.\n", stderr);
        return 1;
    }
    struct node_transport_config config = {
        .endpoint = argv[1], .node_key = getenv("APAZ_NODE_KEY"), .ca_file = getenv("APAZ_NODE_CA"),
        .client_cert = getenv("APAZ_NODE_CERT"), .client_key = getenv("APAZ_NODE_PRIVATE_KEY")
    };
    struct node_health_result result = node_transport_health(&config);
    node_transport_cleanup();
    printf("{\"state\":\"%s\",\"http_status\":%ld}\n", node_health_state_name(result.state), result.http_status);
    return result.state == NODE_HEALTH_AVAILABLE ? 0 : 1;
}
