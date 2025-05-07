#include "dtn_module.h"
#include "dtn_controller.h"
#include "dtn_routing.h"
#include "dtn_storage.h"
#include <stdlib.h> 
#include <stdio.h>  

DTN_Module* dtn_module_init(void) {
    printf("Initializing DTN Module...\n");
    DTN_Module* module = (DTN_Module*)malloc(sizeof(DTN_Module));
    if (!module) {
        perror("Failed to allocate memory for DTN_Module");
        return NULL;
    }

    module->controller = NULL;
    module->routing = NULL;
    module->storage = NULL;

    module->controller = dtn_controller_create(module);
    module->routing = dtn_routing_create(module);
    module->storage = dtn_storage_create(module);

    if (!module->controller || !module->routing || !module->storage) {
        fprintf(stderr, "Failed to create one or more DTN components.\n");
        dtn_module_cleanup(module); 
        return NULL;
    }

    printf("DTN Module initialized successfully.\n");
    return module;
}

void dtn_module_cleanup(DTN_Module* module) {
    if (!module) return;
    printf("Cleaning up DTN Module...\n");

    dtn_controller_destroy(module->controller);
    dtn_routing_destroy(module->routing);
    dtn_storage_destroy(module->storage);

    free(module);
}