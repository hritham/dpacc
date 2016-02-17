/**
 * Copyright (c) 2015, 2016  Freescale.
 *  
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

/*
 * \file dpacc_virtio_flow_api.h
 * 
 * \brief Contains  g_flow_api function declarations & definitions
 *
 * \addtogroup VIRTIO_FLOW
*/

#ifndef _VIRTIO_FLOW_API_H
#define _VIRTIO_FLOW_API_H

/* To be added into virtio header file */
/*! Macros */
/*! Virtio Flow Vendor ID and Device ID  TBD - Defining IDs */
#define VIRTIO_FLOW_VENDOR_ID 0xXXXX
#define VIRTIO_FLOW_DEVICE_ID 0xYYYY

/*! Maximum version length. The version will be of the form major:minor; 
    The Most significant 8 bits will indicate the major number, and remaining 24 bits will indicate the minor number */
#define G_FLOW_MAX_VERSION_LENGTH	32


/*! Success and Failure macros */
#define G_FLOW_FAILURE -1
#define G_FLOW_SUCCESS  0

/*! Flow Device name maximum size */
#define G_FLOW_VIRTUAL_ACCEL_NAME_SIZE	16	

/*! Flow Device application name  maximum size */
#define G_FLOW_ACCEL_APP_NAME_SIZE	16	

/*! Flow Device Port name maximum size */
#define G_FLOW_PORT_NAME_SIZE	16	

/*! Flow Device handle size */
#define G_FLOW_HANDLE_SIZE	8

/*! Maximum table name length possible */
#define G_FLOW_MAX_TABLE_NAME_LEN 32

/* 7 bits Field ID + 1 bit mask + 8 bits length */
#define G_FLOW_MATCH_HEADER__(ID, MASK, LENGTH) (((ID) << 9) | ((MASK) << 8) | (LENGTH))

/*! Match field header with mask not set */
#define G_FLOW_MATCH_HEADER(ID, LENGTH) MATCH_HEADER__(ID, 0, LENGTH)

/*! Match field header with mask set */
#define G_FLOW_MATCH_HEADER_MASK_SET(ID, LENGTH) MATCH_HEADER__(ID, 1, (LENGTH) * 2)


/*! Enumerations */

#if 0
/*! Enums of Port status change event types */
enum g_flow_port_status_event {
        G_FLOW_PORT_ADD = 0, /**< Port added */
        G_FLOW_PORT_MOD = 1, /**< Earlier added Port is modified */
        G_FLOW_PORT_DEL = 2, /**< Earlier added Port to deleted */
};
#endif

/*! Enums of Flow removed reason */
enum g_flow_flow_removed_reason {

     /** Due to inactivity flow removed*/
     G_FLOW_REMOVED_TIMEOUT = 0,

     /** Explict request from application to remove flow*/
     G_FLOW_REMOVED_EXPLICIT = 1,
};

/*! Enums of Reponse code. When application send a query from the accelerator,
  the response will come as part of callback function that passed as part of request with status as defined in enums*/
enum g_flow_response_status {

     /** Response code indicate that success in getting response*/,
     G_FLOW_RESPONSE_STATUS_SUCCESS =1  

     /** Response code indicate that error in getting response*/,
     G_FLOW_RESPONSE_STATUS_ERROR   =2  

     /** Response code indicate that earlier request was timed out*/ 
     G_FLOW_RESPONSE_STATUS_TIMEOUT =3  
};

/*! Enums of Virtual Flow Accelerator objects */
enum g_flow_objects {
    G_FLOW_OBJECT_METER = 0  /**< Flow Meter Object */
};

/*! Enums of match fields , TBD of more fields*/
enum g_flow_match_fields {
    G_FLOW_FIELD_IN_PORT_ID        = 0,  /* Input port. */
    G_FLOW_FIELD_IN_PHY_PORT_ID    = 1,  /* Physical input port. */
    G_FLOW_FIELD_METADATA_ID       = 2,  /* Metadata passed between tables. */
    G_FLOW_FIELD_ETH_DST_ID        = 3,  /* Ethernet destination address. */
    G_FLOW_FIELD_ETH_SRC_ID        = 4,  /* Ethernet source address. */
    G_FLOW_FIELD_ETH_TYPE_ID       = 5,  /* Ethernet frame type. */
    G_FLOW_FIELD_IP_PROTO_ID       = 10, /* IP protocol. */
    G_FLOW_FIELD_IPV4_SRC_ID       = 11, /* IPv4 source address. */
    G_FLOW_FIELD_IPV4_DST_ID       = 12, /* IPv4 destination address. */
    G_FLOW_FIELD_TCP_SRC_ID        = 13, /* TCP source port. */
    G_FLOW_FIELD_TCP_DST_ID        = 14, /* TCP destination port. */
    G_FLOW_FIELD_UDP_SRC_ID        = 15, /* UDP source port. */
    G_FLOW_FIELD_UDP_DST_ID        = 16, /* UDP destination port. */
    G_FLOW_FIELD_ICMPV4_TYPE_ID    = 19, /* ICMP type. */
    G_FLOW_FIELD_ICMPV4_CODE_ID    = 20, /* ICMP code. */
    G_FLOW_FIELD_ARP_OP_ID         = 21, /* ARP opcode. */
    G_FLOW_FIELD_ARP_SPA_ID        = 22, /* ARP source IPv4 address. */
    G_FLOW_FIELD_ARP_TPA_ID        = 23, /* ARP target IPv4 address. */
    G_FLOW_FIELD_ARP_SHA_ID        = 24, /* ARP source hardware address. */
    G_FLOW_FIELD_ARP_THA_ID        = 25, /* ARP target hardware address. */
};


/*! Enums of actions ,TBD more actions */
enum g_flow_actions {

     /** Set specific field value of the packet */
     G_FLOW_AT_SET_PKT_FIELD = 0, 

     /** Send the packet to next specified table */
     G_FLOW_AT_NEXT_TABLE    = 1, 

     /** Trigger an event when packet/byte stats of flow entry reached some threshold value*/ 
     G_FLOW_AT_TRIGGER_FLOW_STATS = 2, 

     /** Packet Rate limiter action by using meter objects */
     G_FLOW_AT_RATE_LIMIT    = 3, 

     /** Set Prirority queue that used before transmitting packet on port */
     G_FLOW_AT_SET_PRIORITY_QUEUE =4, 

     /** Send packet to required port */
     G_FLOW_AT_XMIT_ON_PORT  = 5, 

   /*TBD push and pop tunnel headers*/
   /* TBD  G_FLOW_AT_COPY_FIELD    = 1, equal to set meta data from pkt 
      Copy between header and registers , need to bring packet registers field support*/
};
                  
/*TBD Action Data-Structure, once agreed upon supported actions, will add data-structures*/

/*! Packet Input port match field header*/
#define G_FLOW_IN_PORT    G_FLOW_MATCH_HEADER(G_FLOW_IN_PORT_ID, 4)

/*! Packet Input physical port match field header */
#define G_FLOW_IN_PHY_PORT    G_FLOW_MATCH_HEADER(G_FLOW_IN_PHY_PORT_ID, 4)

/*! Meta data  match field header */
#define G_FLOW_META_DATA             G_FLOW_MATCH_HEADER(G_FLOW_METADATA_ID, 8)
#define G_FLOW_META_DATA_MASK_SET    G_FLOW_MATCH_HEADER_MASK_SET(G_FLOW_METADATA_ID, 8)

/*! Ethernet destination address  match field header */
#define G_FLOW_ETH_DST             G_FLOW_MATCH_HEADER(G_FLOW_ETH_DST_ID, 6)
#define G_FLOW_ETH_DST_MASK_SET    G_FLOW_MATCH_HEADER_MASK_SET(G_FLOW_ETH_DST_ID, 6)

/*! Ethernet source address  match field header */
#define G_FLOW_ETH_SRC             G_FLOW_MATCH_HEADER(G_FLOW_ETH_SRC_ID, 6)
#define G_FLOW_ETH_SRC_MASK_SET    G_FLOW_MATCH_HEADER_MASK_SET(G_FLOW_ETH_SRC_ID, 6)

/*! Ethernet type  match field header */
#define G_FLOW_ETH_TYPE             G_FLOW_MATCH_HEADER(G_FLOW_ETH_TYPE_ID, 2)

/*! IP Porotocol  match field header */
#define G_FLOW_IP_PROTO             G_FLOW_MATCH_HEADER(G_FLOW_IP_PROTO_ID, 1)

/*! IPV4 source address  match field header */
#define G_FLOW_IPV4_SRC             G_FLOW_MATCH_HEADER(G_FLOW_IPV4_SRC_ID, 4)
#define G_FLOW_IPV4_SRC_MASK_SET    G_FLOW_MATCH_HEADER_MASK_SET(G_FLOW_IPV4_SRC_ID, 4)

/*! IPV4 destination address  match field header */
#define G_FLOW_IPV4_DST             G_FLOW_MATCH_HEADER(G_FLOW_IPV4_DST_ID, 4)
#define G_FLOW_IPV4_DST_MASK_SET    G_FLOW_MATCH_HEADER_MASK_SET(G_FLOW_IPV4_DST_ID, 4)

/*! TCP Source Port match field header */
#define G_FLOW_TCP_SRC            G_FLOW_MATCH_HEADER(G_FLOW_TCP_SRC_ID, 2)

/*! TCP Destination  Port match field header */
#define G_FLOW_TCP_DST            G_FLOW_MATCH_HEADER(G_FLOW_TCP_DST_ID, 2)

/*! UDP Source  Port match field header */
#define G_FLOW_UDP_SRC            G_FLOW_MATCH_HEADER(G_FLOW_UDP_SRC_ID, 2)

/*! UDP Destination  Port match field header */
#define G_FLOW_UDP_DST            G_FLOW_MATCH_HEADER(G_FLOW_UDP_DST_ID, 2)

/*! ICPMV4 Type match field header */
#define G_FLOW_ICMPV4_TYPE        G_FLOW_MATCH_HEADER(G_FLOW_ICMPV4_TYPE_ID, 1)

/*! ICPMV4 Code match field header */
#define G_FLOW_ICMPV4_CODE        G_FLOW_MATCH_HEADER(G_FLOW_ICMPV4_CODE_ID, 1)

/*! ARP Header OP Code match field header */
#define G_FLOW_ARP_OP            G_FLOW_MATCH_HEADER(G_FLOW_ARP_OP, 2)

/*! ARP Header Source Protocol address */
#define G_FLOW_ARP_SPA           G_FLOW_MATCH_HEADER(G_FLOW_ARP_SPA_ID, 4)
#define G_FLOW_ARP_SPA_MASK_SET  G_FLOW_MATCH_HEADER_MASK_SET(G_FLOW_ARP_SPA_ID, 4)

/*! ARP Header Destination  Protocol address */
#define G_FLOW_ARP_DPA           G_FLOW_MATCH_HEADER(G_FLOW_ARP_DPA_ID, 4)
#define G_FLOW_ARP_DPA_MASK_SET  G_FLOW_MATCH_HEADER_MASK_SET(G_FLOW_ARP_DPA_ID, 4)

/*! ARP Header Source  Hardware address */
#define G_FLOW_ARP_SHA           G_FLOW_MATCH_HEADER(G_FLOW_ARP_SHA_ID, 6)
#define G_FLOW_ARP_SHA_MASK_SET  G_FLOW_MATCH_HEADER_MASK_SET(G_FLOW_ARP_SHA_ID, 6)

/*! ARP Header Target  Hardware address */
#define G_FLOW_ARP_THA           G_FLOW_MATCH_HEADER(G_FLOW_ARP_THA_ID, 6)
#define G_FLOW_ARP_THA_MASK_SET  G_FLOW_MATCH_HEADER_MASK_SET(G_FLOW_ARP_THA_ID, 6)

/** ingroup VIRTIO_FLOW
* \struct g_flow_avail_devices_get_inargs
* \brief To get Virtual Flow Accelerator devices this passing to g_flow_avail_devices_get_info() as Intargs \n\n
*/
struct g_flow_avail_devices_get_inargs {

     /** Number of devices to get */
     uint32_t num_devices; 

     /** Placed holder for g_flow_avail_devices_get_info() API to return device info,
      *  Application will allocate the memory before calling the API. The size of 
      *  array is 'num_devices'. */    
     struct g_flow_device_info *dev_info; 

     /** NULL if this is the first time this call is invoked. Subsequent calls will 
      *  have a valid value here */											  
     char *last_device_read; 
};

/** ingroup VIRTIO_FLOW
* \struct g_flow_device_info
* \brief Virtual Flow Accelerator Device information  TBD might reuqired to add more Virtual Flow Accelerator details
*/
struct g_flow_device_info {

        /**< Virtual flow accclerator name*/
	char flow_virtual_accel_name[G_FLOW_VIRTUAL_ACCEL_NAME_SIZE]; 
};

/** ingroup VIRTIO_FLOW
* \struct g_flow_avail_devices_get_outargs
* \brief Virtual Flow Accelerator devices info passing to g_flow_avail_devices_get_info() as Outargs \n\n
*/
struct g_flow_avail_devices_get_outargs {

     /** number of devices actually returned which is <= num_devices of  passed 
      *  as part of 'g_flow_avail_devices_get_inargs' */
     uint32_t num_devices; 

     /** Array of pointers, where each points to device specific information */
     struct g_flow_device_info *dev_info; 

     /** Send a value that the application can use and invoke for the next set of devices */
     char *last_device_read; 

     /** Set if more devices are available */
     bool b_more_devices;
};

/** ingroup VIRTIO_FLOW
* \struct g_flow_handle
* \brief Virtual Flow Accelerator device handle \n\n
*
* <b>Description</b>\n
*  Handle of  Virtual Flow Accelerator device. Handle is returned to application when it opens
*  the device. The handle is used for runtime operations before closing device. 
*/
struct g_flow_handle {

     /** Virtual Flow Accelerator handle */
     u8 handle[G_FLOW_HANDLE_SIZE]; 
};

/** ingroup VIRTIO_FLOW
* \struct g_flow_open_virtual_flow_accel_inargs
* \brief Open Virtual Flow Accelerator devices info passing to g_flow_device_open() as Inargs \n\n
*/
struct g_flow_open_virtual_flow_accel_inargs {

     /** Device Id for Virtual Flow Accelerator*/
     uint16_t device_id;

     /** Virtual Flow Accelerator name, 
      *  Format is NAME_IN_STRING#Device_Ref_Index_number */
     char *flow_virtual_accel_name;

     /** Application name which actually openening Virtual Flow Accelerator */ 
     char *application_name;
};

/** ingroup VIRTIO_FLOW
* \struct g_flow_open_virtual_flow_accel_outargs
* \brief Open Virtual Flow Accelerator devices paramters to g_flow_device_open() as Outargs \n\n
*/
struct g_flow_open_virtual_flow_accel_outargs {

     /** Virtual flow acclerator handle */
     struct g_flow_handle *handle; 
};

/** ingroup VIRTIO_FLOW
* \struct g_flow_port_config_inargs
* \brief Configuration values of port attaching to Virtual Flow Accelerator \n\n
*/
struct g_flow_port_config_inargs {

    /** Port number assigned to Virtual Flow Accelerator. This id must be one among ports 
     *  available as part of vnf. But ID number defined here may not be same as port number
     *  of vnf. The mapping betweeen port ID assigned to the accelerator and actual port number
     *  of VNF is application responsibility. */
     uint32_t id;

     /** Name of port assigned to Virtual Flow Accelerator */
     char name[G_FLOW_PORT_NAME_SIZE]; 
};

/** ingroup VIRTIO_FLOW
* \struct g_flow_port_info
* \brief Details of port that attached to Virtual Flow Accelerator \n\n
*/
struct g_flow_port_info {

     /** ID of the port assigned to Virtual Flow Accelerator */
     uint32_t id; 

     /** Name of port assigned to Virtual Flow Accelerator */
     char name[G_FLOW_PORT_NAME_SIZE]; 
};

/** ingroup VIRTIO_FLOW
* \struct g_flow_port_info_cbk_inarg
* \brief Port detais to callback function g_flow_cbk_port_received_fn as inargs\n\n
*/
struct g_flow_port_info_cbk_inarg {

    /** Response status to earlier get port request,  any of G_FLOW_RESPONSE_STATUS_*'  value */
    enum g_flow_response_status response_status; 

    /** Number of port details returned as part of curent response*/ 
    uint32_t num_ports; 

    /** Array of pointers, where each points to port specific information 
     *  defined by 'struct g_flow_port_info' */
    struct g_flow_port_info *port_info; 						

    /** TRUE indicates, this is not final response and more port entries yet to come*/
    uint8_t more_entries; 

    /** Application callback argument 1 that passed earlier as part of g_flow_ports_info_get()  */
    void *cbk_arg1;

    /** Application callback argument 2 that passed earlier as part of g_flow_ports_info_get() */
    void *cbk_arg2;
};

/** ingroup VIRTIO_FLOW
* \typedef g_flow_cbk_port_received_fn
* \brief Callback function to receive details of ports attached to Virtual Flow Acceletator 
*
* <b>Description</b>\n
* The callback will be called after receiving response to the earlier get port request 
* 'g_flow_ports_info_get()' API. For a given get port API request, the callback will be called
*  one or more times  based on the number of ports configured and available resources.  
*
* \param[in] handle- Virtual Flow Accelerator handle  
*
* \param[in] in - Pointer to input structure as defined by 'struct g_flow_port_info_cbk_inarg' 
*
* \returns NONE 
*/
typedef void (*g_flow_cbk_port_received_fn) (
        struct g_flow_handle *handle,
        struct g_flow_port_info_cbk_inarg *in);

/** \ingroup VIRTIO_FLOW
 * \struct g_flow_ports_get_inargs
 * \brief Inargs that passed to g_flow_ports_info_get() API\n\n
 */
struct g_flow_ports_get_inargs {

       /** Pointer to callback function to receive port details */
       g_flow_cbk_table_info_received_fn *port_rcv_cbk;

       /** Application callback argument 1 */
       void *cbk_arg1;

       /** Application callback argument 2 */
       void *cbk_arg2; 
};

/** \ingroup VIRTIO_FLOW
 * \struct g_flow_match_field_info
 * \brief Table match field details \n\n
 */
struct g_flow_match_field_info {

    /** Match Field Id, one of G_FLOW_FIELD* value */ 
    uint32_t id;

    /** TRUE - if field is optional, FALSE - if field is mandatory */ 
    uint8_t  is_optional; 
};

/** \ingroup VIRTIO_FLOW
 * \struct g_flow_packet_notification_inarg
 * \brief Details of packet received from Virtual Flow Acclerator that passing to g_flow_cbk_packet_received_fn() \n\n
 */
struct g_flow_packet_notification_inarg {

     /** Table ID from which packet received */
     uint8_t  table_id;

     /** Length packet data */
     uint32_t packet_len; 

     /** Pointer to packet data */
     uint8_t  *packet_data; 

     /** Application callback argument 1 that configured earlier as part of g_flow_table_add()  */
     void *cbk_arg1;

     /** Application callback argument 2 that configured earlier as part of g_flow_table_add() */
     void *cbk_arg2;
};

/** ingroup VIRTIO_FLOW
* \typedef g_flow_cbk_packet_received_fn
* \brief Callback function to receive packet from Virtual Flow Acceletator 
*
* <b>Description</b>\n
* The accelarator sends packet to application by using this callback. In general accelerator sends packet to application
* incase if it doesn't have any knowledge about handling of the packet it received. That is packet will be sent if 
* accelerator is not programmed with the flow entry. The packet will also be send to the application in case of 
* application needs to receieve every packet. 
*
* \param[in] handle- Virtual Flow Accelerator handle  
*
* \param[in] in - Pointer to input structure as defined by 'struct g_flow_packet_notification_inarg' 
*
* \returns NONE 
*/
typedef void (*g_flow_cbk_packet_received_fn) (
        struct g_flow_handle *handle,
	struct g_flow_packet_notification_inarg *in);

/*! Table removed flow entry information*/

/** \ingroup VIRTIO_FLOW
 * \struct g_flow_table_removed_flow_entry_inarg
 * \brief Details of removed flow entry from a table in Virtual Flow Acclerator that passing to g_flow_cbk_flow_removed_fn()\n\n
 */
struct g_flow_table_removed_flow_entry_inarg {

        /**< Table ID from which flow entry removed*/
        uint8_t  table_id; 

        /** Flow removed reason as defined in G_FLOW_REMOVED* */
        enum g_flow_flow_removed_reason reason; 

        /** Priority of the flow entry */
        uint32_t priority; 

        /** Length of 'match_fields' buffer details as part of flow entry */
        uint32_t match_field_len; 

        /** Pointer to match fields buffer contains list of match field values,
         Each field is defined with 'struct g_flow_match_field'*/
        uint8_t  *match_fields; 

        /** Application callback argument 1 that configured earlier as part of g_flow_table_add()*/
        void *cbk_arg1;

        /** Application callback argument 2 that configured earlier as part of g_flow_table_add()*/
        void *cbk_arg2;
};

/** ingroup VIRTIO_FLOW
* \typedef g_flow_cbk_flow_removed_fn
* \brief Callback function to receive flow entry remove details. 
*
* <b>Description</b>\n
* Application can provide callback function to receive details of flow entry removed from a table 
* in Virtual Flow Accelerator. As part of g_flow_table_add() configuration, application registers 
* this callback. For every flow removed in the accelrator, this callback function will be invoked.
*
* \param[in] handle- Virtual Flow Accelerator handle  
*
* \param[in] in - Pointer to input structure as defined by 'struct g_flow_table_removed_flow_entry_inarg' 
*
* \returns NONE 
*/
typedef void (*g_flow_cbk_flow_removed_fn) (
        struct g_flow_handle *handle,
	struct g_flow_table_removed_flow_entry_inarg *in);

/** \ingroup VIRTIO_FLOW
 * \struct g_flow_table_notification_hooks
 * \brief Configuration of callbacks for the  table adding to Virtual Flow Acclerator\n\n
 */
struct g_flow_table_notification_hooks
{
     /** Packet received callback function, NULL in case no call back function is required */
     struct g_flow_cbk_packet_received_fn  *pkt_rcvd_fn;

     /** Flow Removed Callback function, NULL in case no call back function is required */
     struct g_flow_cbk_flow_removed_fn *flow_rmvd_fn;
	
     /** Packet received callback function argument 1 that used by applications */
     void *packet_rcvd_cbk_arg1;

     /** Packet received callback function argument 2 that used by applications */
     void *packet_rcvd_cbk_arg2;

     /** Flow removed received callback function arguments 1 that used by applications */
     void *flow_rmvd_cbarg_arg1;

     /** Flow removed received callback function arguments 2 that used by applications */
     void *flow_rmvd_cbarg_arg2;
};

/** \ingroup VIRTIO_FLOW
 * \struct g_flow_table_config_inargs
 * \brief Configuration values of table adding to Virtual Flow Acclerator\n\n
 */
struct g_flow_table_config_inargs {

    /** Table Id value, it can be any value between 0 and 254, it must be unique 
     *  for the given Virtual flow acclerator */ 
    uint8_t id; 

    /** Name of the table */
    char name[G_FLOW_MAX_TABLE_NAME_LEN]; 

    /** Maximum number of flow records that supported by the table */
    uint32_t max_records; 

    /** Total number of match fields supported by the table */
    uint32_t match_fields_cnt; 

    /** Array of pointers, where each points to match fields infomation 
        as defined by 'struct g_flow_match_field_info'*/
    struct g_flow_match_field_info *match_field_info;

    /** Pointer to input structure containing notitication callback function and arguments*/
    struct g_flow_table_notification_hooks *cbk_hook_fns; 
};

/** \ingroup VIRTIO_FLOW
 * \struct g_flow_table_info
 * \brief Details of table that added to Virtual Flow Acclerator\n\n
 */
struct g_flow_table_info {

     /** Name of table, basically used for debugging purpose*/
     char name[FLOW_IFNAMESIZ]; 

     /** ID of the table, it can be any value between 0 and 254 */
     uint8_t id; 

     /** Maximum number of flow records that supported by the table */
     uint32_t max_records; 

     /** Total number of match fields supported by the table */
     uint32_t match_fields_cnt; 

     /** Array of pointers, where each points to match field specific information */
     struct g_flow_match_field_info *match_field_info;
};

/** ingroup VIRTIO_FLOW
* \struct g_flow_table_info_cbk_inarg
* \brief Table details to callback function 'g_flow_cbk_table_info_received_fn' as inarg\n\n
*/
struct g_flow_table_info_cbk_inarg {

     /** Response status of earlier get table request, any of G_FLOW_RESPONSE_STATUS_*' value */
     enum g_flow_response_status response_status; 

     /** Number of table details that  actually received as part of curent response*/ 
     uint32_t num_tables; 

     /** Array of pointers, where each points to table specific information */
     struct g_flow_table_info *table_info; 						

     /** TRUE indicates, this is not final response and more table entries yet to come*/
     uint8_t more_entries; 

     /** Application callback argument 1 that passed earlier as part of g_flow_tables_info_get()  */
     void *cbk_arg1;

     /** Application callback argument 2 that passed earlier as part of g_flow_tables_info_get() */
     void *cbk_arg2;
};

/** ingroup VIRTIO_FLOW
* \typedef g_flow_cbk_table_info_received_fn
* \brief Callback function to receive details of tables assigned to Virtual Flow Acceletator 
*
* <b>Description</b>\n
* The callback will be called after receiving response to the earlier get table request 
* 'g_flow_tables_info_get()' API. For a given get table API request, the callback will be 
* called one or more times  based on the number of tables configured and available resources.  
*
* \param[in] handle- Virtual Flow Accelerator handle  
*
* \param[in] in - Pointer to input structure as defined by 'struct g_flow_table_info_cbk_inarg' 
*
* \returns NONE 
*/
typedef void (*g_flow_cbk_table_info_received_fn) (
        struct g_flow_handle *handle,
        struct g_flow_table_info_cbk_inarg *in);

/** ingroup VIRTIO_FLOW
* \struct g_flow_tables_get_inargs
* \brief Arguments passing to g_flow_tables_info_get() API, as inargs, to get table details\n\n
*/
struct g_flow_tables_get_inargs {

     /** Pointer to callback function to receive table details */
     g_flow_cbk_table_info_received_fn *table_rcv_cbk; 

     /** Application callback argument 1 */
     void *cbk_arg1; 

     /** Application callback argument 2 */
     void *cbk_arg2;
};

#if 0
/*! Structure to hold notification from Virtual Flow Accelerator callback functions, 
    The api g_flow_notification_hooks_register()
    is used to register callback functions  */
struct g_flow_notification_hooks {

        struct g_flow_cbk_port_status_change_fn *port_status_change_fn;
        /**< Whenever change in the status of the ports attached virtio flow accelrator, 
           this callback function will be called*/

	/**< Accelerator assocated callback function arguments */
	void *acclerator_assocated_rcvd_cbk_arg1;
	void *acclerator_assocated_rcvd_cbk_arg2;

	/**< Port status change callback function arguments */
	void *port_status_change_cbk_arg1;
	void *port_status_change_cbk_arg2;
};
#endif

/** ingroup VIRTIO_FLOW
* \struct g_flow_match_field
* \brief  Format of each match field value defined as part of match_fileds buffer in the table flow entry 
*/
struct g_flow_match_field {

     /** Match field ID, one of G_FLOW_FIELD_* value */
     uint16_t id:7; 

     /** TRUE means mask value is present after the match field value */
     uint16_t mask:1;

     /** Length of match field value, it will be doubled in case of mask value present  */
     uint16_t length:8;

     /** Value of match field. Along with match field value 'mask value'  will also 
      *  present after match field if 'mask' value is TRUE*/ 
     uint8_t value[0];
};

/** ingroup VIRTIO_FLOW
* \struct g_flow_action
* \brief Format of each action value defined as part of actions bufffer in the table flow entry 
*/
struct g_flow_action 

     /** Action ID, one of G_FLOW_AT_* value */
     uint32_t id; 

     /** Length of action value */ 
     uint32_t length;

     /** Action value, each action will be of diffeent size */ 
     uint8_t  value[0]; 
};

/** ingroup VIRTIO_FLOW
* \struct g_flow_table_flow_entry_selector
* \brief Defines index values for the selection of flow entries in the table 
*/
struct g_flow_table_flow_entry_selector {

     /** Priority value of flow entry, higher number indicates higher priority 
      *  Minimum valid priority value  in flow entry addition is 1. 
      *  Priority value 0 indicates the priority value is not used as index in 
      *  selection of flow entries. */
     uint32_t priority; 

     /** Length of 'match_fields' buffer, zero means match fields are not used 
      *  as index in the selection of flow entries */
     uint32_t match_field_len; 

     /** If 'match_field_len' is more than zero, this is pointer to list of continuous 
      *  variable size match field values, each field value  will be accessed  by using 
      *  'struct g_flow_match_field' format */
     uint8_t  *match_fields;
};

/** ingroup VIRTIO_FLOW
* \struct g_flow_table_add_n_mod_flow_entry_inargs
* \brief Defines inargs parameters for the table flow entry addition and modification APIs
*
* <b>Description</b>\n
*  This data-structures defines input parameter values in the addition and modification of 
*  flow entry APIs g_flow_table_flow_entry_add() and g_flow_table_flow_entry_modify().
*  In case of addition operation, creates new entry in the table with inarg values passed.
*  In case of modification replaces 'inactivity_timeout' and 'action' values of selected
*  selected flow entires by using 'flow_selector'. 
*/
struct g_flow_table_add_n_mod_flow_entry_inargs {

     /** ID of Table ID for which adding or modifying flow */
     uint8_t  table_id; 
 
     /** Table flow entry selector values. In case of addition device creates flow  with the 
      *  'flow_selector values. In case of modification the 'flow_selector is  used to select 
      *  earlier created flow entry */
     struct g_flow_table_flow_entry_selector *flow_selector; 
 
     /** As part of flow entry, it is used to store application specific information which is 
      *  opque to flow api*/
     uint64_t user_opq_val; 
 
     /** Mask used to restrict the 'user_opq_val' bits,*/
     uint64_t user_opq_mask;  

     /** Flow inactivity timeout value in secs. Zero means no timeout and entry is permenant */
     uint32_t inactivity_timeout; 
 
     /** Length of actions supported by the flow entry*/
     uint32_t actions_len;

     /** Pointer to list of variable size action values of flow entry,each action value will be 
         created and accessed by using 'struct g_flow_action' */
     uint8_t  *actions; 
};

/** ingroup VIRTIO_FLOW
* \struct g_flow_table_del_flow_entires_inarg
* \brief Defines inargs parameters for the table flow entry deletion API g_flow_table_flow_entry_delete()
*/
struct g_flow_table_del_flow_entires_inarg {

     /** Table Id from which deleting flow entries*/
     uint8_t  table_id;  

     /** Flow entry selector value used to select flow entries that created earlier in the Virtual Flow 
         Accelerator . All the selected flow entries are deleted */
     struct g_flow_table_flow_entry_selector *flow_selector;
};

/** ingroup VIRTIO_FLOW
* \struct g_flow_table_flow_entry
* \brief Details flow entry creted in the table 
*/
struct g_flow_table_flow_entry{

      /** Priority value of flow entry */
      uint32_t priority; 

      /** Length of 'match_fields' buffer*/
      uint32_t match_field_len; 

      /** Pointer to list of variable size match field values, each will be accessed by using 
          'struct g_flow_match_field'*/
      uint8_t  *match_fields;

      /** Application Opaque value used to store application specific information*/
      uint64_t user_opq_val;  

      /** Mask used to restrict the 'user_opq_val' bits,*/
      uint64_t user_opq_mask; 

      /** Flow inactivity timeout value in secs. Zero means no timeout*/
      uint32_t inactivity_timeout; 

      /** Number of Packetes processed by the flow entry */
      uint64_t num_of_pkts_proc 

      /**  Number of bytes processed the the flow entry*/
      uint64_t num_of_bytes_proc;

      /** System up time in seconds at which first packet hit the flow entry */        
      uint64_t first_pkt_time;

      /** System up time in seconds at which last packet hit the flow entry */        
      uint64_t last_pkt_time;

      /** Length of actions values supported  by the flow entry*/
      uint32_t actions_len;

      /** Pointer to list of, variable size, action values of flow entry,
           each action value will be accessed by using 'struct g_flow_action' */
      uint8_t  *actions; 
};

/** ingroup VIRTIO_FLOW
* \struct g_flow_table_flow_entires_cbk_inarg
* \brief Details of flow entry passing to g_flow_cbk_flow_entries_received_fn() cbk as inargs 
*/
struct g_flow_table_flow_entires_cbk_inarg {

     /**  Table id to which the flow entries belongs */
     uint8_t table_id; 

     /** Response status of earlier get flow request,  any of G_FLOW_RESPONSE_STATUS_*'  value */
     enum g_flow_response_status response_status; 

     /**  Number of flow entries returned in the current iteration */
     uint32_t number_of_flow_entries; 

     /** Array contains list of flow entry, each entry points to flow entry information */
     struct g_flow_table_flow_entry *flow_entries; 

     /**  TRUE indicates, this is not final response and more flow entries yet to come*/
     uint8_t more_entries; 

     /** Application callback argument 1 that passed earlier as part of g_flow_table_flow_entry_get()  */
     void *cbk_arg1;

     /** Application callback argument 2 that passed earlier as part of g_flow_table_flow_entry_get() */
     void *cbk_arg2;
};

/** ingroup VIRTIO_FLOW
* \typedef g_flow_cbk_flow_entries_received_fn
* \brief Callback function to receive details of flow entry of tables assigned to Virtual Flow Acceletator 
*
* <b>Description</b>\n
* Callback function that application can provide to receive selected flow entries of a table in the 
* accelerator. The callback will be called after receiving response to the earlier get flow request 
* 'g_flow_table_flow_entry_get()' API. For a given get flow entry API request, the callback will be 
* called one or more times  based on the number of flows selected and available resources.  
*
* \param[in] handle- Virtual Flow Accelerator handle  
*
* \param[in] in - Pointer to input structure as defined by 'struct g_flow_table_flow_entires_cbk_inarg' 
*
* \returns NONE 
*/
typedef void (*g_flow_cbk_flow_entries_received_fn) (
        struct g_flow_handle *handle,
        struct g_flow_table_flow_entires_cbk_inarg *in);

/** ingroup VIRTIO_FLOW
* \struct g_flow_table_get_flow_entires_inarg
* \brief Parameters passing to g_flow_table_flow_entry_get() as inargs 
*/
struct g_flow_table_get_flow_entires_inarg {

     /** Table Id from which flow entries returned*/
     uint8_t  table_id;  

     /**  Selector values, all selected flow entries passed to callback function asynchronusly */  
     struct g_flow_table_flow_entry_selector *flow_selector; 

     /**  Pointer to callback function to receive flow entries */
     g_flow_cbk_flow_entries_received_fn *flow_rcv_cbk; 

     /** Application callback argument 1 */
     void *cbk_arg1; 

     /** Application callback argument 2 */
     void *cbk_arg2; 
};

/** ingroup VIRTIO_FLOW
* \struct g_flow_meter_object
* \brief Meter object, data-structure used for Object type 'G_FLOW_OBJECT_METER' 
*/
struct g_flow_meter_object {

     /** Id of the meter object, it MUST be unique value */
     uint32_t id; 

     /*TBD of adding more fields */
};

/** ingroup VIRTIO_FLOW
* \struct g_flow_object_entry_inarg
* \brief Parameters that passed to g_flow_object_entry_add() as inargs 
*/
struct g_flow_object_entry_inarg {

     /** One of object Type, one of G_FLOW_OBJECT_*  */
     enum g_flow_objects type; 

     /** Length of object value  */
     uint32_t length;

     /**  Actual object value, seperate data-structure for each object type */ 
     uint8_t  value[0]; 
};

/*! Flow object callback functions in args */

/** ingroup VIRTIO_FLOW
* \struct g_flow_object_entry_cbk_inarg
* \brief Parameters passing to g_flow_object_entry_add() as inargs 
*/
struct g_flow_object_entry_cbk_inarg { 

     /** Response status of earlier object request, any of G_FLOW_RESPONSE_STATUS_*'  value */
     enum g_flow_response_status response_status; 

     /** Type of object, one of G_FLOW_OBJECT_* */
     enum g_flow_objects type;

     /** Pointer to object entry contains earlier requested object  details  */ 
     void *object;

     /** Application callback argument 1 */
     void *cbk_arg1;

     /** Application callback argument 2 */
     void *cbk_arg2;
};

/** ingroup VIRTIO_FLOW
* \typedef g_flow_cbk_object_entries_received_fn
* \brief Callback function to receive object details from Virtual Flow Acceletator 
*
* <b>Description</b>\n
* Callback function that application can provide to receive object of geven type from 
* accelerator. The callback will be called after receiving response to the earlier get object request 
* 'g_flow_object_entry_get()' API. 
*
* \param[in] handle- Virtual Flow Accelerator handle  
*
* \param[in] in - Pointer to input structure as defined by 'struct g_flow_object_entry_cbk_inarg' 
*
* \returns NONE 
*/
typedef void (*g_flow_cbk_object_entries_received_fn) (
        struct g_flow_handle *handle,
        struct g_flow_object_entry_cbk_inarg *in);

/** ingroup VIRTIO_FLOW
* \struct g_flow_object_entry_inarg
* \brief Parameters that passed to g_flow_object_entry_get() as inargs 
*/
struct g_flow_get_object_inargs {

     /** Id of the object to get details */
     uint32_t id; 

     /** Object type, one of G_FLOW_OBJECT_*  */
     uint32_t type;

     /** Pointer to callback function to receive object details */
     g_flow_cbk_object_entries_received_fn *object_rcv_cbk; 

     /** Application callback argument 1 */
     void *cbk_arg1;

     /** Application callback argument 2 */
     void *cbk_arg2;
};

/*! Function prototypes */

/** \ingroup VIRTIO_FLOW 
 * \brief This API returns the API version.
 *
 * \param[in/out] version - Version string
 * 
 * \returns G_FLOW_SUCCESS upon success or G_FLOW_FAILURE 
 *
 * \ingroup VIRTIO_FLOW
 */
int32_t g_flow_api_version(char *version);

/*! 
 * \brief Get the number of available devices 
 *
 * \param[in/out] nr_devices - Number of devices 
 *
 * \returns G_FLOW_SUCCESS upon success or G_FLOW_FAILURE
 *
 * \ingroup VIRTIO_FLOW
 */
int32_t g_flow_avail_devices_get_num(uint32_t *nr_devices); 

/*!
 * \brief  Get the avaialble device info  
 *
 * \param[in] in -  Pointer to input structure
 *
 * \param[out] out - Pointer to output structure containing device information
 *
 * \returns G_FLOW_SUCCESS upon success or G_FLOW_FAILURE 
 *
 * \ingroup VIRTIO_FLOW
 */
int32_t g_flow_avail_devices_get_info(
	struct g_flow_avail_devices_get_inargs *in,
	struct g_flow_avail_devices_get_outargs *out);

#if 0
/*!
 * \brief Register for notifications from Virtual Flow Accelerator
 *
 * \param[in] flow_virtual_accel_name- Virtual Flow Accelerator name to which registering callback functions 
 * \param[in] application_name - Application which registering with Virtual Flow Accelerator 
 *
 * \param[in]  in - Pointer to input structure containing notitication callback function and arguments.
 *                  NULL is passed for the functions that are registering.
 *
 * \returns G_FLOW_SUCCESS upon success or G_FLOW_FAILURE
 *
 * \ingroup VIRTIO_IPSEC
 */
int32_t g_flow_notification_hooks_register (
        char *flow_virtual_accel_name,
        char *applicaton_name,
	const struct g_flow_notification_hooks *in);
#endif

/*! 
 * \brief Open an Virtual flow acclerator device.
 *        Create instance of the device or processing context in Virtual flow acclerator.
 *
 * \param[in] in - Pointer to input structure
 *
 * \param[out] out -Pointer to output structure with accelerator instance handle. 
 *                  Applications uses the handler for its subsequent operations before close.
 *
 * \returns G_FLOW_SUCCESS upon success or G_FLOW_FAILURE
 *
 * \ingroup VIRTIO_FLOW
 */
int32_t g_flow_device_open(
	struct g_flow_open_virtual_flow_accel_inargs *in,
	struct g_flow_open_virtual_flow_accel_outargs *out);

/*! 
 * \brief Add port to previously opened Virtual Flow Accelerator 
 *
 * \param[in] handle- Virtual Flow Accelerator handle 
 * 
 * \param[in] port_cnfg - Pointer to port  configuration values.
 *
 * \returns G_FLOW_SUCCESS upon success or G_FLOW_FAILURE
 *
 * \ingroup VIRTIO_FLOW
 */
int32_t g_flow_port_add(struct g_flow_handle *handle,
                        struct g_flow_port_config_inargs *port_cnfg);

/*! 
 * \brief Get the number of ports that assiged the given Virtual Flow Accelerator 
 *
 * \param[out] nr_ports - Number of ports 
 *
 * \returns G_FLOW_SUCCESS upon success or G_FLOW_FAILURE
 *
 * \ingroup VIRTIO_FLOW
 */
int32_t g_flow_ports_get_num(uint32_t *nr_ports); 

/*!
 * \brief  Get the ports info of given Virtual Flow Accelerator  
 *
 * \param[in] handle- Virtual Flow Accelerator handle 
 *
 * \param[in] in -  Pointer to input structure
 *
 * \param[out] out - Pointer to output structure containing port information
 *
 * \returns G_FLOW_SUCCESS upon success or G_FLOW_FAILURE 
 *
 * \ingroup VIRTIO_FLOW
 */
int32_t g_flow_ports_info_get(struct g_flow_handle *handle,
                              struct g_flow_ports_get_inargs *in);


/*! 
 * \brief Add table to previously opened Virtual Flow Accelerator 
 *
 * \param[in] handle- Virtual Flow Accelerator handle 
 * 
 * \param[in] table_cnfg - Pointer to table  configuration values.
 *
 * \returns G_FLOW_SUCCESS upon success or G_FLOW_FAILURE
 *
 * \ingroup VIRTIO_FLOW
 */
int32_t g_flow_table_add(struct g_flow_handle *handle,
                         struct g_flow_table_config_inargs *table_cnfg);

/*! 
 * \brief Get the number of tables configured for the given Virtual Flow Accelerator 
 *
 * \param[in] handle- Virtual Flow Accelerator handle 
 *
 * \param[in/out] nr_tables - Number of tables 
 *
 * \returns G_FLOW_SUCCESS upon success or G_FLOW_FAILURE
 *
 * \ingroup VIRTIO_FLOW
 */
int32_t g_flow_tables_get_num(struct g_flow_handle *handle,
                              uint32_t *nr_tables); 

/*!
 * \brief  Get the tables info of given Virtual Flow Accelerator  
 *
 * \param[in] handle- Virtual Flow Accelerator handle 
 *
 * \param[in] in -  Pointer to input structure
 *
 * \returns G_FLOW_SUCCESS upon success or G_FLOW_FAILURE 
 *
 * \ingroup VIRTIO_FLOW
 */
int32_t g_flow_tables_info_get(struct g_flow_handle *handle,
                               struct g_flow_tables_get_inargs *in);

/*! 
 * \brief After completing configuration of the accelerator, usually after adding 
 *        all tables, all ports applications calls this API. This is way for 
 *        application to inform Virtual Flow Accelerator that it completed all 
 *        its configuration and it is ready to use. 
 *
 *
 * \param[in] handle- Virtual Flow Accelerator handle 
 *
 * \returns G_FLOW_SUCCESS upon success or G_FLOW_FAILURE
 *
 * \ingroup VIRTIO_FLOW
 */
int32_t g_flow_application_ready(struct g_flow_handle *handle); 


/*!
 * \brief  Add flow entry into given table of a Virtual Flow Accelerator  
 *
 * \param[in] handle- Virtual Flow Accelerator handle 
 *
 * \param[in] in -  Pointer to input structure contains flow entry details
 *
 * \returns G_FLOW_SUCCESS upon success or G_FLOW_FAILURE 
 *
 * \ingroup VIRTIO_FLOW
 */
int32_t g_flow_table_flow_entry_add(struct g_flow_handle *handle,
                                    struct g_flow_table_add_n_mod_flow_entry_inargs *in);
/*!
 * \brief  Modify flow entry of a table in a Virtual Flow Accelerator  
 *
 * \param[in] handle- Virtual Flow Accelerator handle 
 *
 * \param[in] in -  Pointer to input structure contains flow entry details
 *
 * \returns G_FLOW_SUCCESS upon success or G_FLOW_FAILURE 
 *
 * \ingroup VIRTIO_FLOW
 */
int32_t g_flow_table_flow_entry_modify(struct g_flow_handle *handle,
                                       struct g_flow_table_add_n_mod_flow_entry_inargs *in);

/*!
 * \brief  Delete a selected flow entres of a table in a Virtual Flow Accelerator  
 *
 * \param[in] handle- Virtual Flow Accelerator handle 
 *
 * \param[in] in -  Pointer to input structure contains flow entry selector details 
 *
 * \returns G_FLOW_SUCCESS upon success or G_FLOW_FAILURE 
 *
 * \ingroup VIRTIO_FLOW
 */
int32_t g_flow_table_flow_entry_delete(struct g_flow_handle *handle,
                                       struct g_flow_table_del_flow_entires_inarg *in);

/*! 
 * \brief Get flow entry details of for the required selctor value s of a Virtual Flow Accelerator 
 *
 * \param[in] handle- Virtual Flow Accelerator handle 
 *
 * \param[in] in -  Pointer to input structure contains flow entry selectors, callbacks, etc.  
 *
 * \returns G_FLOW_SUCCESS upon success or G_FLOW_FAILURE
 *
 * \ingroup VIRTIO_FLOW
 */
int32_t g_flow_table_flow_entry_get(struct g_flow_handle *handle,
                                    struct g_flow_table_get_flow_entires_inarg *in);
/*!
 * \brief  Add object entry in a Virtual Flow Accelerator  
 *
 * \param[in] handle- Virtual Flow Accelerator handle 
 *
 * \param[in] in -  Pointer to input structure contains object entry details. 
 *
 * \returns G_FLOW_SUCCESS upon success or G_FLOW_FAILURE 
 *
 * \ingroup VIRTIO_FLOW
 */
int32_t g_flow_object_entry_add(struct g_flow_handle *handle,
                                struct g_flow_object_entry_inarg *in);

/*!
 * \brief  Modify object entry in a Virtual Flow Accelerator  
 *
 * \param[in] handle- Virtual Flow Accelerator handle 
 *
 * \param[in] in -  Pointer to input structure contains object entry details. 
 *
 * \returns G_FLOW_SUCCESS upon success or G_FLOW_FAILURE 
 *
 * \ingroup VIRTIO_FLOW
 */
int32_t g_flow_object_entry_modify(struct g_flow_handle *handle,
                                   struct g_flow_object_entry_inarg *in);

/*!
 * \brief  Delete object entry from Virtual Flow Accelerator  
 *
 * \param[in] handle- Virtual Flow Accelerator handle 
 *
 * \param[in] type - Type of object table from which deleting object
 *
 * \param[in] id - Id of the object to delete
 *
 * \returns G_FLOW_SUCCESS upon success or G_FLOW_FAILURE 
 *
 * \ingroup VIRTIO_FLOW
 */
int32_t g_flow_object_entry_delete(struct g_flow_handle *handle,
                                   enum g_flow_objects type, 
                                   uint32_t id);
/*!
 * \brief  Get the object info of given Virtual Flow Accelerator  
 *
 * \param[in] handle- Virtual Flow Accelerator handle 
 *
 * \param[in] in -  Pointer to input structure contains to get object details
 *
 * \returns G_FLOW_SUCCESS upon success or G_FLOW_FAILURE 
 *
 * \ingroup VIRTIO_FLOW
 */
int32_t g_flow_object_entry_get(struct g_flow_handle *handle,
                                struct g_flow_get_object_inargs *in);
/*
 * \brief Send packet to Virtual Flow Accelerator.The attached actions to the packet will be executed at accelerator  
 *
 * \param[in] handle- Virtual Flow Accelerator handle 
 *
 * \param[in] pkt_data_len - Length of the packet data sending to the accelelrator 
 *
 * \param[in] pkt_data  - Pointer to packet data 
 *
 * \param[in] action_len - Length of actions attached to packet data that executed at accelerator
 *
 * \param[in] actions - Pointer to action buffer contains list of actions  
 *
 * \returns G_FLOW_SUCCESS upon success or G_FLOW_FAILURE
 *
 * \ingroup VIRTIO_FLOW
*/
int32_t g_flow_send_packet(struct g_flow_handle *handle,
                           uint32_t pkt_data_len,
                           uint8_t *pkt_data,
                           uint32_t action_len,
                           uint8_t  *actions);
/*!
 * \brief Close a previously opened  Virtual Flow Accelerator device  
 *
 * \param[in] handle- Virtual Flow Accelerator handle 
 *
 * \returns G_FLOW_SUCCESS upon success or G_FLOW_FAILURE
 *
 * \ingroup VIRTIO_FLOW
 */
int32_t g_flow_device_close(struct g_flow_handle *handle);

#endif
