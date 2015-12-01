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
 * @file dpacc_virtio_flow_api.h
 * 
 * @brief Contains  g_flow_api function declarations & definitions
 *
 * @addtogroup VIRTIO_FLOW
 * @{
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

#define G_FLOW_MATCH_HEADER__(ID, MASK, LENGTH) (((ID) << 9) | ((MASK) << 8) | (LENGTH))

/*! Match field header with mask not set */
#define G_FLOW_MATCH_HEADER(ID, LENGTH) MATCH_HEADER__(ID, 0, LENGTH)

/*! Match field header with mask set */
#define G_FLOW_MATCH_HEADER_MASK_SET(ID, LENGTH) MATCH_HEADER__(ID, 1, (LENGTH) * 2)


/*! Enumerations */

/*! Enums of Port status change event types */
enum g_flow_port_status_event {
        G_FLOW_PORT_ADD = 0, /**< Port added */
        G_FLOW_PORT_MOD = 1, /**< Earlier added Port is modified */
        G_FLOW_PORT_DEL = 2, /**< Earlier added Port to deleted */
};

/*! Enums of Reponse code. When application send a query from the accelerator,
  the response will come as part of callback function that passed as part of request with status as defined in enums*/
enum g_flow_response_status {
     G_FLOW_RESPONSE_STATUS_SUCCESS =1  /**< Response code indicate that success in getting response*/,
     G_FLOW_RESPONSE_STATUS_ERROR   =2  /**< Response code indicate that error in getting response*/,
     G_FLOW_RESPONSE_STATUS_TIMEOUT =3  /**< Response code indicate that earlier request was timed out*/ 
};

/*! Enums of virtual flow accelerator objects */
enum g_flow_objects {
    G_FLOW_GROUP_OBJECT = 0, /**<< Flow Group Object */
    G_FLOW_METER_OBJECT = 1  /**< Flow Meter Object */
};

/*! Enums of match fields , TBD of more fields*/
enum g_flow_match_fields {
    G_FLOW_IN_PORT_ID        = 0,  /* Input port. */
    G_FLOW_IN_PHY_PORT_ID    = 1,  /* Physical input port. */
    G_FLOW_METADATA_ID       = 2,  /* Metadata passed between tables. */
    G_FLOW_ETH_DST_ID        = 3,  /* Ethernet destination address. */
    G_FLOW_ETH_SRC_ID        = 4,  /* Ethernet source address. */
    G_FLOW_ETH_TYPE_ID       = 5,  /* Ethernet frame type. */
    G_FLOW_IP_PROTO_ID       = 10, /* IP protocol. */
    G_FLOW_IPV4_SRC_ID       = 11, /* IPv4 source address. */
    G_FLOW_IPV4_DST_ID       = 12, /* IPv4 destination address. */
    G_FLOW_TCP_SRC_ID        = 13, /* TCP source port. */
    G_FLOW_TCP_DST_ID        = 14, /* TCP destination port. */
    G_FLOW_UDP_SRC_ID        = 15, /* UDP source port. */
    G_FLOW_UDP_DST_ID        = 16, /* UDP destination port. */
    G_FLOW_ICMPV4_TYPE_ID    = 19, /* ICMP type. */
    G_FLOW_ICMPV4_CODE_ID    = 20, /* ICMP code. */
    G_FLOW_ARP_OP_ID         = 21, /* ARP opcode. */
    G_FLOW_ARP_SPA_ID        = 22, /* ARP source IPv4 address. */
    G_FLOW_ARP_TPA_ID        = 23, /* ARP target IPv4 address. */
    G_FLOW_ARP_SHA_ID        = 24, /* ARP source hardware address. */
    G_FLOW_ARP_THA_ID        = 25, /* ARP target hardware address. */
};


/*! Enums of actions ,TBD more actions */
enum g_flow_actions {
    G_FLOW_AT_SET_PKT_FIELD = 0, /* Set specific field value of the packet */
    G_FLOW_AT_NEXT_TABLE    = 2, /* Send the packet to next specified table */
    G_FLOW_AT_TRIGGER_FLOW_STATS = 3, /* Trigger an event when packet/byte stats of flow entry reached some threshold value*/ 
    G_FLOW_AT_RATE_LIMIT    = 3, /* Packet Rate limiter action by using meter objects */
    G_FLOW_AT_SET_PRIORITY_QUEUE =4, /* Set Prirority queue that used before transmitting packet on port */
    G_FLOW_AT_XMIT_ON_PORT  = 5, /* Send packet to required port */

   /*TBD push and pop tunnel headers*/
   /* TBD  G_FLOW_AT_COPY_FIELD    = 1, equal to set meta data from pkt  Copy between header and registers , need to bring packet registers field support*/
};
                  

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

/*! Get Available flow devices inArgs */
struct g_flow_avail_devices_get_inargs {
	uint32_t num_devices; /**< Number of devices to get */
	char *last_device_read; 
	/**< NULL if this is the first time this call is invoked;
          Subsequent calls will have a valid value here */											  
};

/*! Flow Device information  TBD might reuqired to add more virtual flow accelerator details*/ 
struct g_flow_device_info {
	char flow_virtual_accel_name[G_FLOW_VIRTUAL_ACCEL_NAME_SIZE]; /**< Device name  of flow accclerator*/
};

/*! Avaialble flow devices get outArgs */
struct g_flow_avail_devices_get_outargs {
	uint32_t num_devices; /**< number of devices recieved */
	struct g_flow_device_info *dev_info; 						
	/**< Array of pointers, where each points to device specific information */
	char *last_device_read; 
	/**< Send a value that the application can use and invoke for the next set of devices */
	bool b_more_devices;
	/**< Set if more devices are available */
};

/*! Handles */
struct g_flow_handle {
	u8 handle[G_FLOW_HANDLE_SIZE]; /**< Virtual Flow Accelerator handle */
};

/*! Virtual Flow Accelerator Open inArgs */
struct g_flow_open_virtual_flow_accel_inargs {
	uint16_t pci_vendor_id; /**< PCI Vendor ID 0xXXXX */
	uint16_t device_id;     /**< Device Id for flow  accelerator*/
	char *flow_virtual_accel_name; /**< Flow virtual accelerator name */
        char *accel_application_name; /**< Application name which actually openening virtual flow accelerator */ 
};

/*! Virtual Flow Accelerator Open OutArgs */
struct g_flow_open_virtual_flow_accel_outargs {
        struct g_flow_handle *handle; /** virtual flow acclerator handle */
};

/*! Port Info*/
struct g_flow_port_info {
     uint32_t id; /**< ID of the port assigned to flow accelerator */
     char name[G_FLOW_PORT_NAME_SIZE]; /**< Name of port assigned to flow accelerator */
};

/*! Get Port details of given flow accelerator inArgs */
struct g_flow_ports_get_inargs {
	uint32_t num_ports; /**< Number of ports to get */
	char *last_port_read; 
	/**< NULL if this is the first time this call is invoked;
          Subsequent calls will have a valid value here */											  
};

/*! Get Port  information Virtual Flow Acceletator get outArgs */
struct g_flow_ports_get_outargs {
	uint32_t num_ports; /**< number of ports to get */
	struct g_flow_port_info *port_info; 						
	/**< Array of pointers, where each points to port specific information */
	char *last_port_read; 
	/**< Send a value that the application can use and
	  * invoke for the next set of ports */
	bool b_more_ports;
	/**< Set if more ports are available */
};

/*! Callback function prototype that application can provide to receive virtio flow accelrater associated event,
    OpenStack creates virtio flow accelarator and associates with vnf.
    As part of this event handler, the application opens virtio flow accelerator device by using g_flow_device_open()  API */
typedef void (*g_flow_cbk_accelator_associated_fn) (
        char *flow_virtual_accel_name,
        char *accel_application_name,
        void *cbk_arg1, 
        void *cbk_arg2);

/*! Port status change event info*/
struct g_flow_port_status {
      enum g_flow_port_status_event event_type; /**< Type of port status change event */
      struct g_flow_port_info port_info; /**< Details of port which changed status */
};

/*! Callabck function prototype that application to receive event when there is change in the run time port status change*/ 
typedef void (*g_flow_cbk_port_status_change_fn) (
        struct g_flow_handle *handle,
        struct g_flow_port_status port_status,
        void *cbk_arg1,
        void *cbk_arg2);

/*! Structure to hold notification from virtual flow accelerator callback functions, The api g_flow_notification_hooks_register()
    is used to register callback functions  */
struct g_flow_notification_hooks {
	struct g_flow_cbk_accelator_associated_fn  *accelator_associated_fn;
	/**< Accelator associated  vNF callback function. For every VNF, OpenStack creates  vertio flow accelerator and 
         * exposed to VNF. */

        struct g_flow_cbk_port_status_change_fn *port_status_change_fn;
        /**< Whenever change in the status of the ports attached virtio flow accelrator, this callback function will be called*/

	/**< Accelerator assocated callback function arguments */
	void *acclerator_assocated_rcvd_cbk_arg1;
	void *acclerator_assocated_rcvd_cbk_arg2;

	/**< Port status change callback function arguments */
	void *port_status_change_cbk_arg1;
	void *port_status_change_cbk_arg2;
};

/*! Packet notification details from table of given virtual flow accelator TBD might required to add more fields*/
struct g_flow_packet_notification {
        uint8_t  table_id; /**< Table ID from which packet is received */
        uint32_t packet_len; /**< Length packet data */
        uint8_t  *packet_data; /**< Pointer to packet data */
};

/*! Callback function prototype that application can provide to receive packet from virtual flow acclerator */
typedef void (*g_flow_cbk_packet_received_fn) (
        struct g_flow_handle *handle,
	struct g_flow_packet_notification *in,
        void *cbk_arg1,
        void *cbk_arg2);

/*! Table removed flow entry information*/
struct g_flow_table_removed_flow_entry {
        uint8_t  table_id; /**< Table ID of flow entry removed*/
        uint32_t priority; /**< priority of flow entry */
        uint32_t match_field_len; /**< Length of 'match_fields' buffer */
        uint8_t  *match_fields; /**< Pointer to match fields buffer contains list of match field values,
                                    Each field is defined with 'struct g_flow_match_field'*/
};

/*! Callback function prototype that application can provide to receive flow removed event from virtual flow acclerator */
typedef void (*g_flow_cbk_flow_removed_fn) (
        struct g_flow_handle *handle,
	struct g_flow_table_removed_flow_entry *in, /**> Flow entry that removed from table*/
        void *cbk_arg1,
        void *cbk_arg2);

/*! Structure to hold notification from tables of given virtual flow acclerator callback functions */
struct g_flow_table_notification_hooks
{
	/**< Packet received callback function, NULL in case no call back function is required */
	struct g_flow_cbk_packet_received_fn  *pkt_rcvd_fn;
	/**< Flow Removed Callback function, NULL in case no call back function is required */
	struct g_flow_cbk_flow_removed_fn *flow_rmvd_fn;
	
	/**< Packet received callback function arguments */
	void *packet_rcvd_cbk_arg1;
	void *packet_rcvd_cbk_arg2;

	/**< Flow removed received callback function arguments */
	void *flow_rmvd_cbarg_arg1;
	void *flow_rmvd_cbarg_arg2;
};

/*! Table Match field information */
struct g_flow_match_field_info {
  uint32_t id; /**< Match Field Id  TBD defining list of match fields supported*/
  uint8_t  is_optional; /**< TRUE - if field is optional, FALSE - if field is mandatory */ 
};

/*! Table configuration values for the virtual flow acclerator */ 
struct g_flow_table_config_inargs {
  uint8_t id; /**< Table Id value, it can be any value between 0 and 254, it must be unique for the given virtual flow acclerator */ 
  char name[G_FLOW_MAX_TABLE_NAME_LEN]; /**< Name of the table */
  uint32_t max_records; /**< Maximum number of flow records that supported by the table */
  uint32_t match_fields_cnt; /**< Total number of match fields supported by the table */
  struct g_flow_match_field_info *match_field_info;
  struct g_flow_table_notification_hooks *cbk_hook_fns; /**< Pointer to input structure containing notitication callback function and arguments*/
};

/*! Flow Table information */ 
struct g_flow_table_info {
	char name[FLOW_IFNAMESIZ]; /**< Device name */
        uint8_t id; /**< Id of the table */
        uint32_t max_records; /**< Maximum number of flow records that supported by the table */
        uint32_t match_fields_cnt; /**< Total number of match fields supported by the table */
        struct g_flow_match_field_info *match_field_info;
	/**< Array of pointers, where each points to match field specific information */
};

/*! Get flow table details of given virtual flow acclerator inArgs */
struct g_flow_tables_get_inargs {
	uint32_t num_tables; /**< Number of tables to get */
	char *last_table_read; 
	/**< NULL if this is the first time this call is invoked;
          Subsequent calls will have a valid value here */											  
};

/*! Flow tables information get outArgs */
struct g_flow_tables_get_outargs {
	uint32_t num_tables; /**< number of tables returned */
	struct g_flow_table_info *table_info; 						
	/**< Array of pointers, where each points to
	    table specific information */
	char *last_table_read; 
	/**< Send a value that the application can use and
	  * invoke for the next set of tables */
	bool b_more_tables;
	/**< Set if more tables are available */
};

/*! Format of each match field values as part of match_fileds buffer created in the table flow entry */
struct g_flow_match_field {
        uint16_t id:7; /**< Match field ID */
        uint16_t mask:1; /**< TRUE means mask value is present after the match field value */
        uint16_t length:8; /**< Length of match field value, it will be doubled in case of mask value present  */
        uint8_t value[0]; /**< Match field value. Along with match field value 'mask value'  will also present if 'mask' value is TRUE*/ 
};

/* ! Format of each action value as part of actions  bufffer of the table flow entry */
struct g_flow_action {
       uint32_t id; /**< Action ID */
       uint32_t length; /**< Length of action value */ 
       uint8_t  value[0]; /**< Action value, each action will have diffeent size */ 
};

/*! Select a flow entry in a table*/
struct g_flow_table_flow_entry_selector {
        uint32_t priority; /**< Priority value of flow entry, higher number indicates higher priority 
                                Minimum valid priority value  in flow entry addition is 1, Priority value 0 indicates the priority value
                                is not used as parameter in the selection for flow entires. */
        uint32_t match_field_len; /**< Length of 'match_fields' buffer, zero value no match fields in the selection of flow entries*/
        uint8_t  *match_fields; /**< Pointer to list of variable size match field values, 
                                    each will be created and accessed by using 'struct g_flow_match_field'*/
};

/*! Table flow entry information used as input argument value in the addition and modification of flow entry API
    In case of modification replaces 'inactivity_timeout' and 'action' values of selected
    selected flow entires */
struct g_flow_table_add_n_mod_flow_entry_inargs {
        uint8_t  table_id; /**< Table ID to which adding or modifying flow */
        struct g_flow_table_flow_entry_selector flow_selector; /**< Table flow entry selector values */ 
        uint64_t user_opq_val;  /** <Opaque value, for flow api,  as part of flow entry, to store application specific information*/
        uint64_t user_opq_mask;  /** <Mask used to restrict the 'user_opq_val' bits,*/
        uint32_t inactivity_timeout; /**< Flow inactivity timeout value in secs. Zero means no timeout*/
        uint32_t actions_len;/**< Length of actions supported  by the flow entry*/
        uint8_t  *actions; /**< Pointer to list of variable size action values of flow entry,
                                each action value will be created and accessed by using 'struct g_flow_action' */
};

/* ! Flow entry deletion function in_args */
struct g_flow_table_del_flow_entires_inarg {
        uint8_t  table_id;  /** <Table Id from which deleting flow entries*/
        struct g_flow_table_flow_entry_selector *flow_selector; /** < Selector values, selected flow entries are deleted */  
};

/* ! Details for table flow entry */
struct g_flow_table_flow_entry{
        uint32_t priority; /**< priority value of flow entry */
        uint32_t match_field_len; /**< Length of 'match_fields' buffer*/
        uint8_t  *match_fields; /**< Pointer to list of variable size match field values, 
                                    each will be accessed by using 'struct g_flow_match_field'*/

        uint64_t user_opq_val;  /** <Opaque value, for flow api,  as part of flow entry, to store application specific information*/
        uint64_t user_opq_mask;  /** <Mask used to restrict the 'user_opq_val' bits,*/

        uint32_t inactivity_timeout; /**< Flow inactivity timeout value in secs. Zero means no timeout*/

        uint64_t num_of_pkts_proc /**< Number of Packetes processed by the flow */
        uint64_t num_of_bytes_proc; /** < Number of bytes processed the the flow */
        uint64_t first_pkt_time; /** <System up time in seconds at which first packet hit the flow */        
        uint64_t last_pkt_time; /** <System up time in seconds at which last packet hit the flow */        

        uint32_t actions_len;/**< Length of actions values supported  by the flow entry*/
        uint8_t  *actions; /**< Pointer to list of, variable size, action values of flow entry,
                                each action value will be accessed by using 'struct g_flow_action' */
};

/* ! Flow entry receive callback function in_args , parameters passed to flow entries received callback function */
struct g_flow_table_flow_entires_cbk_inarg {
        uint8_t table_id; /** < Table id to which the flow entries belongs*/
        enum g_flow_response_status response_status; /** <Response status of earlier flow request */
        uint32_t number_of_flow_entries; /** < Number of flow entries returned in this iteration */
        struct g_flow_table_flow_entry *flow_entries; /**< Array contains list of flow entry details */
        uint8_t more_entries; /** < TRUE indicates, this is not final response and more flow entries yet to come*/
        void *cbk_arg1; /** <Application callback argument 1 */
        void *cbk_arg2; /** <Application callback argument 2 */
};

/*! Callback function prototype that application can provide to receive selected flow entries of a table in the accelerator */
typedef void (*g_flow_cbk_flow_entries_received_fn) (
        struct g_flow_handle *handle,
        struct g_flow_table_flow_entires_cbk_inarg *in);

/* ! Get Flow entries function in_args */
struct g_flow_table_get_flow_entires_inarg {
        uint8_t  table_id;  /** <Table Id from which getting flow entries*/
        struct g_flow_table_flow_entry_selector *flow_selector; /** < Selector values, all selected flow entries passed to 
                                                                      callback function asynchronusly */  
        g_flow_cbk_flow_entries_received_fn *flow_rcv_cbk; /** < Pointer to callback function to receive flow entries */
        void *cbk_arg1; /** <Application callback argument 1 */
        void *cbk_arg2; /** <Application callback argument 2 */
};

/*! Group object, data-structure used for Object type 'G_FLOW_GROUP_OBJECT' */
struct g_flow_group_object {
       uint32_t id; /**< Id of the group object, it MUST be unique value */

/*TBD of adding more fields */
};

/*! Meter object, data-structure used for Object type 'G_FLOW_METER_OBJECT' */
struct g_flow_meter_object {
       uint32_t id; /**< Id of the meter object, it MUST be unique value */

/*TBD of adding more fields */
};

/*! Inargs for the addition/modification of objects in a virutal flow accelerator*/
struct g_flow_object_entry_inarg {
       uint32_t type; /**< One of object Type defined in 'enum g_flow_objects'  */
       uint32_t length; /**< Length of object value  */
       uint8_t  value[0]; /**<  Actual object value, seperate data-structure for each object type */ 
};

/*! Flow object callback functions in args */
struct g_flow_object_entry_cbk_inarg { 
       enum g_flow_response_status response_status; /** <Response status of earlier object request */
       uint32_t type; /** Type of object */
       void *object; /**< Pointer to object entry contains earlier requested object  details  */ 
       void *cbk_arg1; /** <Application callback argument 1 */
       void *cbk_arg2; /** <Application callback argument 2 */
};

/*Callback function proototype to received object details */
typedef void (*g_flow_cbk_object_entries_received_fn) (
        struct g_flow_handle *handle,
        struct g_flow_object_entry_cbk_inarg *in);

/*! Get object inargs */
struct g_flow_get_object_inargs {
       uint32_t id; /**< Id of the object to get details */
       uint32_t type; /**< object type  */
       g_flow_cbk_object_entries_received_fn *object_rcv_cbk; /**< Pointer to callback function to received object details */
       void *cbk_arg1; /** <Application callback argument 1 */
       void *cbk_arg2; /** <Application callback argument 2 */
};

/*! Function prototypes */
/*! 
w_table_flow_entry
 * @brief This API returns the API version.
 *
 * @param[in/out] version - Version string
 * 
 * @returns SUCCESS upon SUCCESS or FAILURE 
 *
 * @ingroup VIRTIO_FLOW
 */
int32_t g_flow_api_version(char *version);

/*! 
 * @brief Get the number of available devices 
 *
 * @param[in/out] nr_devices - Number of devices 
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_FLOW
 */
int32_t g_flow_avail_devices_get_num(uint32_t *nr_devices); 

/*!
 * @brief  Get the avaialble device info  
 *
 * @param[in] in -  Pointer to input structure
 *
 * @param[out] out - Pointer to output structure containing device information
 *
 * @returns SUCCESS upon SUCCESS or failure 
 *
 * @ingroup VIRTIO_FLOW
 */
int32_t g_flow_avail_devices_get_info(
	struct g_flow_avail_devices_get_inargs *in,
	struct g_flow_avail_devices_get_outargs *out);

/*!
 * @brief Register for notifications from virtual flow accelerator
 *
 * @param[in] flow_virtual_accel_name- virtual flow accelerator name to which registering callback functions 
 * @param[in] application_name - Application which registering with virtual flow accelerator 
 *
 * @param[in]  in - Pointer to input structure containing notitication callback function and arguments.
 *                  NULL is passed for the functions that are registering.
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t g_flow_notification_hooks_register (
        char *flow_virtual_accel_name,
        char *applicaton_name,
	const struct g_flow_notification_hooks *in);

/*! 
 * @brief Open an virtual flow acclerator device.
 *
 * @param[in] in - Pointer to input structure
 *
 * @param[out] out -Pointer to output structure with accelerator handle 
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_FLOW
 */
int32_t g_flow_device_open(
	struct g_flow_open_virtual_flow_accel_inargs *in,
	struct g_flow_open_virtual_flow_accel_outargs *out);

/*! 
 * @brief Get the number of ports that assiged the given virtual flow accelerator 
 *
 * @param[in/out] nr_ports - Number of ports 
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_FLOW
 */
int32_t g_flow_ports_get_num(uint32_t *nr_tables); 

/*!
 * @brief  Get the ports info of given virtual flow accelerator  
 *
 * @param[in] handle- virtual flow accelerator handle 
 *
 * @param[in] in -  Pointer to input structure
 *
 * @param[out] out - Pointer to output structure containing port information
 *
 * @returns SUCCESS upon SUCCESS or failure 
 *
 * @ingroup VIRTIO_FLOW
 */
int32_t g_flow_ports_get_info(struct g_flow_handle *handle,
                              struct g_flow_ports_get_inargs *in,
	                      struct g_flow_ports_get_outargs *out);
/*! 
 * @brief Add table to previously opened virtual flow accelerator 
 *
 * @param[in] handle- virtual flow accelerator handle 
 * 
 * @param[in] table_cnfg - Pointer to table  configuration values.
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_FLOW
 */
int32_t g_flow_table_add(struct g_flow_handle *handle,
                         struct g_flow_table_config_inargs *table_cnfg);
/*! 
 * @brief After completing configuration the accelerator, usually after adding all tables, applications calls this API.
 *
 * @param[in] handle- virtual flow accelerator handle 
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_FLOW
 */
int32_t g_flow_application_ready(struct g_flow_handle *handle); 

/*! 
 * @brief Get the number of tables configured for the given virtual flow accelerator 
 *
 * @param[in] handle- virtual flow accelerator handle 
 *
 * @param[in/out] nr_tables - Number of tables 
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_FLOW
 */
int32_t g_flow_tables_get_num(struct g_flow_handle *handle,
                              uint32_t *nr_tables); 

/*!
 * @brief  Get the tables info of given virtual flow accelerator  
 *
 * @param[in] handle- virtual flow accelerator handle 
 *
 * @param[in] in -  Pointer to input structure
 *
 * @param[out] out - Pointer to output structure containing table information
 *
 * @returns SUCCESS upon SUCCESS or failure 
 *
 * @ingroup VIRTIO_FLOW
 */
int32_t g_flow_tables_info_get(struct g_flow_handle *handle,
                               struct g_flow_tables_get_inargs *in,
	                       struct g_flow_tables_get_outargs *out);
/*!
 * @brief  Add flow entry into given table of a virtual flow accelerator  
 *
 * @param[in] handle- virtual flow accelerator handle 
 *
 * @param[in] in -  Pointer to input structure contains flow entry details
 *
 * @returns SUCCESS upon SUCCESS or failure 
 *
 * @ingroup VIRTIO_FLOW
 */
int32_t g_flow_table_flow_entry_add(struct g_flow_handle *handle,
                                    struct g_flow_table_add_n_mod_flow_entry_inargs *in);
/*!
 * @brief  Modify flow entry of a table in a virtual flow accelerator  
 *
 * @param[in] handle- virtual flow accelerator handle 
 *
 * @param[in] in -  Pointer to input structure contains flow entry details
 *
 * @returns SUCCESS upon SUCCESS or failure 
 *
 * @ingroup VIRTIO_FLOW
 */
int32_t g_flow_table_flow_entry_modify(struct g_flow_handle *handle,
                                       struct g_flow_table_add_n_mod_flow_entry_inargs *in);

/*!
 * @brief  Delete a selected flow entres of a table in a virtual flow accelerator  
 *
 * @param[in] handle- virtual flow accelerator handle 
 *
 * @param[in] in -  Pointer to input structure contains flow entry selector details 
 *
 * @returns SUCCESS upon SUCCESS or failure 
 *
 * @ingroup VIRTIO_FLOW
 */
int32_t g_flow_table_flow_entry_delete(struct g_flow_handle *handle,
                                       struct g_flow_table_del_flow_entires_inarg *in);

/*! 
 * @brief Get flow entry details of for the required selctor value s of a virtual flow accelerator 
 *
 * @param[in] handle- virtual flow accelerator handle 
 *
 * @param[in] in -  Pointer to input structure contains flow entry selectors, callbacks, etc.  
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_FLOW
 */
int32_t g_flow_table_flow_entry_get(struct g_flow_handle *handle,
                                    struct g_flow_table_get_flow_entires_inarg *in);
/*!
 * @brief  Add object entry in a virtual flow accelerator  
 *
 * @param[in] handle- virtual flow accelerator handle 
 *
 * @param[in] in -  Pointer to input structure contains object entry details. 
 *
 * @returns SUCCESS upon SUCCESS or failure 
 *
 * @ingroup VIRTIO_FLOW
 */
int32_t g_flow_object_entry_add(struct g_flow_handle *handle,
                                struct g_flow_object_entry_inarg *in);

/*!
 * @brief  Modify object entry in a virtual flow accelerator  
 *
 * @param[in] handle- virtual flow accelerator handle 
 *
 * @param[in] in -  Pointer to input structure contains object entry details. 
 *
 * @returns SUCCESS upon SUCCESS or failure 
 *
 * @ingroup VIRTIO_FLOW
 */
int32_t g_flow_object_entry_modify(struct g_flow_handle *handle,
                                   struct g_flow_object_entry_inarg *in);

/*!
 * @brief  Delete object entry from virtual flow accelerator  
 *
 * @param[in] handle- virtual flow accelerator handle 
 *
 * @param[in] type - Type of object table from which deleting object
 *
 * @param[in] id - Id of the object to delete
 *
 * @returns SUCCESS upon SUCCESS or failure 
 *
 * @ingroup VIRTIO_FLOW
 */
int32_t g_flow_object_entry_delete(struct g_flow_handle *handle,
                                   enum g_flow_objects type, 
                                   uint32_t id);
/*!
 * @brief  Get the object info of given virtual flow accelerator  
 *
 * @param[in] handle- virtual flow accelerator handle 
 *
 * @param[in] in -  Pointer to input structure contains to get object details
 *
 * @returns SUCCESS upon SUCCESS or failure 
 *
 * @ingroup VIRTIO_FLOW
 */
int32_t g_flow_object_entry_get(struct g_flow_handle *handle,
                                struct g_flow_get_object_inargs *in);
/*
 * @brief  Send packet to virtual flow accelerator. The attached actions to packet will be executed at accelerator  
 *
 * @param[in] handle- virtual flow accelerator handle 
 *
 * @param[in] pkt_data_len - Length of the packet data sending to the accelelrator 
 *
 * @param[in] pkt_data  - Pointer to packet data 
 *
 * @param[in] action_len - Length of actions attached to packet data that executed at accelerator
 *
 * @param[in] actions - Pointer to action buffer contains list of actions  
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_FLOW
*/
int32_t g_flow_send_packet(struct g_flow_handle *handle,
                           uint32_t pkt_data_len,
                           uint8_t *pkt_data,
                           uint32_t action_len,
                           uint8_t  *actions);
/*!
 * @brief Close a previously opened  virtual flow accelerator device  
 *
 * @param[in] handle- virtual flow accelerator handle 
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_FLOW
 */
int32_t g_flow_device_close(struct g_flow_handle *handle);

#endif
