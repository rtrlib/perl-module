#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include "rtrlib/rtrlib.h"

#include "ppport.h"


MODULE = RPKI::RTRlib		PACKAGE = RPKI::RTRlib		

rtr_mgr_config *
start(host, port)
    const char* host;
    const char* port;
    CODE:
    //create a TCP transport socket
    tr_socket *tr_tcp = malloc(sizeof(tr_socket));
    tr_tcp_config tcp_config1 = {
        host,          //IP
        port           //Port
    };
    tr_tcp_init(&tcp_config1, tr_tcp);
    
    rtr_socket *rtr_tcp = malloc(sizeof(rtr_socket));
    rtr_tcp->tr_socket = tr_tcp;
    rtr_mgr_group *groups = malloc(1 * sizeof(rtr_mgr_group));
    
    groups[0].sockets = malloc(1 * sizeof(rtr_socket*));
    groups[0].sockets_len = 1;
    groups[0].sockets[0] = rtr_tcp;
    groups[0].preference = 1;       //Preference value of this group
    
    //create a rtr_mgr_config struct that stores the group
    rtr_mgr_config *conf = malloc(sizeof(rtr_mgr_config));
    conf->groups = groups;
    conf->len = 1;                   //1 elements in the groups array
    //initialize all rtr_sockets in the server pool with the same settings
    rtr_mgr_init(conf, 240, 520, NULL);
    //start the connection manager
    rtr_mgr_start(conf);
    //wait till at least one rtr_mgr_group is fully synchronized with the server
    while(!rtr_mgr_conf_in_sync(conf))
        sleep(1);
    
    RETVAL = conf;
    OUTPUT:
    RETVAL

int
validate(conf, asn,ipAddr, cidr)
    rtr_mgr_config *conf;
    int asn;
    char* ipAddr;
    int cidr;
    CODE:
    ip_addr pref;
    ip_str_to_addr(ipAddr, &pref);
    pfxv_state result;
    
    rtr_mgr_validate(conf, asn, &pref, cidr, &result);
    
    RETVAL = result;

    OUTPUT:
    RETVAL

SV *
validate_r(conf, asn,ipAddr,cidr)
    rtr_mgr_config *conf;
    int asn;
    char *ipAddr;
    int cidr;
    
    INIT:
    HV * results;
    results = (HV *) sv_2mortal ((SV *) newHV());
    AV * alist;
    alist = (AV *) sv_2mortal ((SV *) newAV());
    
    CODE:
    ip_addr pref;
    ip_str_to_addr(ipAddr, &pref);
    pfx_record *reason = malloc(sizeof(pfx_record));
    int *reason_len = malloc(sizeof(int));
    pfxv_state result;
    pfx_table_validate_r(conf->groups[0].sockets[0]->pfx_table,&reason,reason_len, asn, &pref, cidr, &result);
    
    hv_store(results,"state",5,newSViv(result),0);
    
    int i;
    for(i=0;i<(*reason_len);i++){
        char stripAddr[INET6_ADDRSTRLEN];
        ip_addr_to_str(&reason[i].prefix,stripAddr,INET6_ADDRSTRLEN);
        HV * roa = (HV *) sv_2mortal((SV *)newHV());
        hv_store(roa,"asn",3,newSViv(reason[i].asn),0);
        hv_store(roa,"max",3,newSViv(reason[i].max_len),0);
        hv_store(roa,"min",3,newSViv(reason[i].min_len),0);
        hv_store(roa,"prefix",6,newSVpv(stripAddr,strlen(stripAddr)),0);
        av_push(alist,newRV((SV *)roa));
        
    }
    hv_store(results,"roas",4,newRV((SV *)alist),0);
    RETVAL = newRV((SV *)results);
    OUTPUT:
    RETVAL

void
DESTROY(conf)
    rtr_mgr_config *conf ;
    CODE:
    rtr_mgr_stop(conf);
    rtr_mgr_free(conf);
    
    int i,j;
    for(i=0;i<conf->len;i++){
        for(j=0;j<conf->groups[i].sockets_len;j++){
            free(conf->groups[i].sockets[j]->tr_socket);
            free(conf->groups[i].sockets[j]);
        }
        free(conf->groups[i].sockets);
    }
    free(conf);

void
stop(conf)
    rtr_mgr_config *conf ;
    CODE:
    rtr_mgr_stop(conf);
    rtr_mgr_free(conf);
    
    int i,j;
    for(i=0;i<conf->len;i++){
        for(j=0;j<conf->groups[i].sockets_len;j++){
            free(conf->groups[i].sockets[j]->tr_socket);
            free(conf->groups[i].sockets[j]);
        }
        free(conf->groups[i].sockets);
    }
    free(conf);

