 /*
 * Copyright 2015 Freescale Semiconductor
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * \file virtio_flow_msg.h
 * 
 * \brief Contains  virtio_flow_msg declarations & definitions
 *
 * \addtogroup VIRITO_FLOW_MESSAGE
*/
#ifndef _VIRTIO_FLOW_MSG_H
#define _VIRTIO_FLOW_MSG_H

/*! Success and Failure macros */
#define VIRTIO_FLOW_FAILURE -1
#define VIRTIO_FLOW_SUCCESS  0


#define VIRTIO_PORT_NAME_LEN G_FLOW_PORT_NAME_SIZE

/** ingroup VIRITO_FLOW_MESSAGE
 *! Enums values of result */
enum virtio_flow_result_value
{       
        /** Result is Ok */
        VIRTIO_FLOW_OK = 0,    

        /** Result is an error */
        VIRTIO_FLOW_ERR        
}; 

/** ingroup VIRITO_FLOW_MESSAGE
 * \struct virtio_flow_ctrl_hdr
 *  Flow accelerator header format of message sending on control virtqueue
 *      
 * The control virtqueue expects a header in the first sg entry
 * and an result/status response in the last entry.  Data for the
 * command goes in between.
 * Note: The ctrl_hdr, ctrl_result and the actual command 
 * can be sent as a single buffer as well
 */
struct virtio_flow_ctrl_hdr {

       /** Class of the command in the message */
        uint8_t class;  

       /** Actual command id for the given class */
        uint8_t cmd;   

       /** The handle of flow accelerator instance for which sending/receiving
        *  command. Each created flow accelerator instance is expected to maintain
        *  unique 64 bit  handle as device identification.
        *
        *  In case of VIRTIO_FLOW_CREATE_ACCEL command, this field  value 
        *  is ignored. 
        */
       uint64_t accel_handle;

       /** Total length of the message including control header and following data
        * if any.*/
       uint32_t length;
}__attribute__((packed)); 

/** ingroup VIRITO_FLOW_MESSAGE
 * \struct virtio_flow_ctrl_result
 * Data structure for result of the message sent earlier on control virtqueue */
struct virtio_flow_ctrl_result {

        /** VIRTIO_FLOW_OK or VIRTIO_FLOW_ERR */
        enum virtio_flow_result_value result;   

        /** Length of the result data returned */
        uint32_t  data_len;

        /** More result information,if any. In case data exists, the content of 
          * data will be accessed by seperate independent data-structure based on  
          * result received for which command type. 
          * One example is error description, here it is a stream of bytes. 
          * To access error description no separate data-structure is required. 
          * Another example is flow accelerate handle. As part of result data to the
          * command VIRTIO_FLOW_CREATE_ACCEL returns unique 64 bit handle. 
          * The same handle will be used for subsequent commands sending to the 
          * corresponding flow accelertor.
          */
        uint8_t* data; 
}__attribute__((packed));

/** ingroup VIRITO_FLOW_MESSAGE
* \struct g_flow_accel_info
* \brief information of flow accelerator and application which creating instnace
*/
struct virtio_flow_accel_info {

     /** Flow Accelerator name*/ 
     uint8_t flow_accel_name[G_FLOW_ACCEL_NAME_SIZE+1];

     /** Application name which actually creating Flow Accelerator instnace */
     uint8_t application_name[G_FLOW_ACCEL_APP_NAME_SIZE +1];
} __attribute__((packed));

/** ingroup VIRITO_FLOW_MESSAGE
* \struct virtio_flow_port_config_info
* \brief Configuration details of port attaching to flow acceleration instnace
*/
struct virtio_flow_port_config_info {

    /** Port number assigned to Flow Accelerator. This id must be one among ports 
     *  available as part of guest. */
     uint32_t id;

     /** Name of port assigned to Flow Accelerator instance */
     uint8_t name[VIRTIO_PORT_NAME_LEN];
}__attribute__((packed));

/** ingroup VIRITO_FLOW_MESSAGE
* \struct virtio_flow_port_info_reply
* \brief Details of ports that attached to flow acceleration instnace
*/
struct virtio_flow_port_info_reply {

     /** TRUE indicates, this is not final response and more port entries yet to come*/
     uint8_t more_entries;

     /** Number of port entry details returned as part of curent response, included for
      *  debugging purpose */
     uint8_t num_entries; 

     /** Contains array of 'struct g_flow_port_info' entries */
     uint8_t port_info[];
}__attribute__((packed));

/** ingroup VIRITO_FLOW_MESSAGE
* \struct virtio_flow_stage_config_info
* \brief Configuration details of packet processing stage adding to flow acceleration instnace
*/
struct virtio_flow_proc_stage_config_info {

    /** Id of processing stage, it can be any value between 0 and 254, it must be unique 
     *  for the given flow acclerator instance */ 
    uint8_t id; 

    /** Name of the processing stge */
    uint8_t name[G_FLOW_MAX_TABLE_NAME_LEN]; 

    /** It will set to TRUE in case of processing stage is first one to process packet.
     *  Atleast one processing stage must need to define as first one */  
    uint8_t is_first_stage;

    /** Maximum number of flow records that supported by the flow table in processing stage */
    uint32_t max_records; 

    /** Total number of match fields supported by the flow table, used for debugging 
     *  purpose*/
    uint32_t match_fields_cnt; 

    /** Array of match filed value defined by 'struct g_flow_match_field_info' */
    uint8_t match_fields[];
}__attribute__((packed));

/** ingroup VIRITO_FLOW_MESSAGE
* \struct virtio_flow_proc_stage_info_reply
* \brief Details of processing stages that attached to flow acceleration instnace
*/   
struct virtio_flow_proc_stage_info_reply {

     /** TRUE indicates, this is not final response and more proc stage entries yet to come*/
     uint8_t more_entries;

     /** Number of packet processing stage entry details returned as part of curent 
      *  response, included for debugging purpose */
     uint8_t num_stages; 

     /** Contains array of 'struct g_flow_stage_info' entries */
     uint8_t proc_stage_info[];
}__attribute__((packed));

/** ingroup VIRITO_FLOW_MESSAGE
* \struct virtio_flow_add_entry_to_proc_stage
* \brief Details of add flow entry to processing stages that attached to flow acceleration instnace
*/   
struct virtio_flow_add_entry_to_proc_stage {

    /** ID of processing stage to which adding flow entry */
    uint8_t  stage_id;

    /** Priority value of flow entry, higher number indicates higher priority 
     *  Minimum valid priority value  in flow entry addition is 1. 
     */
    uint32_t priority;

    /** As part of flow entry, it is used to store application specific information*/
    uint64_t user_opq_val;

    /** Mask used to restrict the 'user_opq_val' bits,*/
    uint64_t user_opq_mask;

    /** Flow inactivity timeout value in secs. Zero means no timeout and entry is permenant */
    uint32_t inactivity_timeout;
   
    /** Length of 'match_fields'*/ 
     uint32_t match_field_len;

    /** Variable size match field values */
    struct g_flow_match_field match_fields[];

    /** Variable size actions, length of action buffer will be extracted from control header */ 
    /* struct g_flow_action actions[0]; */

}__attribute__((packed));

/** ingroup VIRITO_FLOW_MESSAGE
* \struct virtio_flow_modify_entry_to_proc_stage
* \brief Details of modify flow entry message to processing stages that attached to flow acceleration instnace
* <b> description <\b>
*  The 'priority' and 'match_fields' are used to select flow entry to modify with new 'inactivity_timeout
*  and 'actions' 
*/   
struct virtio_flow_modify_entry_of_proc_stage {

    /** ID of processing stage to which modifying flow entry */
    uint8_t  stage_id;

    /** Priority value of flow entry, higher number indicates higher priority 
     *  Minimum valid priority value  in flow entry addition is 1. 
     */
    uint32_t priority;

    /** Flow inactivity timeout value in secs. Zero means no timeout and entry is permenant */
    uint32_t inactivity_timeout;
   
    /** Length of 'match_fields' buffer*/
     uint32_t match_field_len;

    /** Variable size match field values */
    struct g_flow_match_field match_fields[];

    /** Variable size actions, length of action buffer will be extracted from control header */ 
    /* struct g_flow_action actions[0]; */

}__attribute__((packed));

/** ingroup VIRITO_FLOW_MESSAGE
* \struct virtio_flow_delete_entry_to_proc_stage
* \brief Details of delete flow entry message to processing stages that attached to flow acceleration instnace
* <b> description <\b>
*  The 'priority' and 'match_fields' are used to select flow entry to delete
*/   
struct virtio_flow_delete_entry_from_proc_stage {

    /** ID of processing stage from which deleting flow entry */
    uint8_t  stage_id;

    /** Priority value of flow entry, higher number indicates higher priority 
     *  Minimum valid priority value  in flow entry addition is 1. 
     */
    uint32_t priority;

    /** Length of 'match_fields'*/
     uint32_t match_field_len;

    /** Variable size match field values */
    struct g_flow_match_field match_fields[];

}__attribute__((packed));

/** ingroup VIRITO_FLOW_MESSAGE
* \struct virtio_flow_proc_stage_entry_info_reply
* \brief Details of processing stage flow entries 
*/   
struct virtio_flow_proc_stage_entry_info_reply {

     /** TRUE indicates, this is not final response and more flow entries yet to come*/
     uint8_t more_entries;

     /** Number of flow entry details returned as part of curent response, included for debugging purpose */
     uint8_t num_entries; 

     /** Contains array of 'struct g_flow_stage_flow_entry' values */
     uint8_t entry_info[];
}__attribute__((packed));


typedef struct g_flow_stage_object_entry_inarg virtio_flow_stage_object_config_info_t;

/** ingroup VIRITO_FLOW_MESSAGE
* \struct virtio_flow_delete_stage_object_config_info_t
* \brief Details of objects deleting for the given object type of given processing stage */
struct virtio_flow_delete_stage_object_config_info_t {

    /** ID of processing stage from which deleting object entry */
    uint8_t  stage_id;

    /** Type of object from which deleting object, one of G_FLOW_OBJECT_* */
    enum g_flow_objects type;

    /** Id of the object of given 'type' from which deleting object, 
     *  It can also be 'G_FLOW_OBJECT_ALL' for deletion of all objects of given 'type'*/
    uint32_t id;
}__attribute__((packed));

/** ingroup VIRITO_FLOW_MESSAGE
* \struct virtio_flow_proc_stage_entry_info_reply
* \brief Details of object entries of given type of processing stage  
*/   
struct virtio_flow_proc_stage_object_entry_info_reply {

     /** ID of processing stage from which getting object entry(s) */
     uint8_t  stage_id;

     /** Type of object for which reply received, one of G_FLOW_OBJECT_* */
     enum g_flow_objects type;

     /**  TRUE indicates, this is not final response and more object values yet to come*/
     uint8_t more_entries;

     /**  Number of object values returned in the current itration */
     uint32_t number_of_objects;

     /** Array contains list of object values , each entry points to object information
         each value is acessed with correspding object type definition */
     uint8_t object_values[0];
}__attribute__((packed));

typedef struct g_flow_object_entry_inarg virtio_flow_object_config_info_t;

/** ingroup VIRITO_FLOW_MESSAGE
* \struct virtio_flow_delete_object_config_info_t
* \brief Details of objects deleting for the given object type  */
struct virtio_flow_delete_object_config_info_t {

    /** Type of object from which deleting object, one of G_FLOW_OBJECT_* */
    enum g_flow_objects type;

    /** Id of the object of given 'type' from which deleting object, 
     *  It can also be 'G_FLOW_OBJECT_ALL' for deletion of all objects of given 'type'*/
    uint32_t id;
}__attribute__((packed));


/** ingroup VIRITO_FLOW_MESSAGE
* \struct virtio_flow_entry_info_reply
* \brief Details of object entries of given type
*/   
struct virtio_flow_object_entry_info_reply {

     /** Type of object for which reply received, one of G_FLOW_OBJECT_* */
     enum g_flow_objects type;

     /**  TRUE indicates, this is not final response and more object values yet to come*/
     uint8_t more_entries;

     /**  Number of object values returned in the current itration */
     uint32_t number_of_objects;

     /** Array contains list of object values , each entry points to object information
         each value is acessed with correspding object type definition */
     uint8_t object_values[0];
}__attribute__((packed));

/** ingroup VIRITO_FLOW_MESSAGE
*! Message types sending to control queue */
enum virtio_flow_ctrl_msg_class {

    /** Class of message used to manage flow accelrator instance */
    VIRTIO_FLOW_ACCEL_MGMT = 1,

    /** Class of message used manage ports attaching to flow accelerator instance */
    VIRTIO_FLOW_ACCEL_PORT_MGMT,

    /** Class of message used manage packet processing stage attaching to flow 
     *  accelerator instance */
    VIRTIO_FLOW_ACCEL_PROC_STAGE_MGMT,

    /** Class of message used manage objects of flow  accelerator instance */
    VIRTIO_FLOW_ACCEL_OBJECT_MGMT
};

/*! Size of flow accelerator instance creation message*/
#define VIRTIO_FLOW_MSG_CREATE_ACCEL_SIZE \
        (sizeof(struct virtio_flow_ctrl_hdr)+      \
         sizeof(struct virtio_flow_accel_info)+    \
         sizeof(struct virtio_flow_ctrl_result)       )

/*! Size of flow accelerator instance application ready message*/
#define VIRTIO_FLOW_MSG_ACCEL_APP_READY_TO_USE_SIZE \
        (sizeof(struct virtio_flow_ctrl_hdr)

/*! Size of flow accelerator instance delete message*/
#define VIRTIO_FLOW_MSG_DELETE_ACCEL_SIZE \
        (sizeof(struct virtio_flow_ctrl_hdr)

/** ingroup VIRITO_FLOW_MESSAGE
*! Commands used to manage flow accelerator instnace */
enum virtio_flow_ctrl_cmd_class_instance_mgmt {

     /** Command to create flow accelertor instance */
     VIRTIO_FLOW_CREATE_ACCEL = 1, 

     /** Command to inform accelrator that application completed all its
      *  confiugration and is ready to use. The configuration usually includes
      *  port additions, defining multiple packet processing stages, etc. */
     VIRTIO_FLOW_ACCEL_READY_TO_USE,

     /** Command to delete earlier created flow accelertor instance */
     VIRTIO_FLOW_DELETE_ACCEL 
};

/*! Size of add port to flow accelerator instance message*/
#define VIRTIO_FLOW_ADD_PORT_ACCEL_SIZE \
        (sizeof(struct virtio_flow_ctrl_hdr)+    \
         sizeof(struct virtio_flow_port_config_info)+   \
         sizeof(struct virtio_flow_ctrl_result)       )

/*! Size of get ports of flow accelerator instance request message*/
#define VIRTIO_FLOW_GET_PORT_ACCEL_REQUEST_SIZE \
        (sizeof(struct virtio_flow_ctrl_hdr)       )

/*! Size of get port details of flow accelerator instance reply message*/
#define VIRTIO_FLOW_GET_PORT_ACCEL_REPLY_SIZE \
        (sizeof(struct virtio_flow_ctrl_hdr)+    \
         sizeof(struct virtio_flow_port_info_reply)

/** ingroup VIRITO_FLOW_MESSAGE
*! Commands used to manage port attaching flow accelerator instnace */
enum virtio_flow_ctrl_cmd_class_port_mgmt {

     /** Message to add port flow accelertor instance */
     VIRTIO_FLOW_ADD_PORT_ACCEL = 1, 

     /** Message to get details of ports attached to flow accelerator instance */
     VIRTIO_FLOW_GET_ACCEL_PORTS_INFO_REQUEST,

     /** Reply Message to  earlier 'VIRTIO_FLOW_GET_ACCEL_PORTS_INFO_REQUEST' 
      *  command */
     VIRTIO_FLOW_GET_ACCEL_PORTS_INFO_REPLY
};

/*! Size of add packet processing stage to flow accelerator instance message*/
#define VIRTIO_FLOW_ATTACH_PROC_STAGE_ACCEL_SIZE \
        (sizeof(struct virtio_flow_ctrl_hdr)+    \
         sizeof(struct virtio_flow_proc_stage_config_info)+   \
         sizeof(struct virtio_flow_ctrl_result)       )

/*! Size of  get packet processing stages of  flow accelerator instance request message*/
#define VIRTIO_FLOW_GET_PROC_STAGE_ACCEL_REQUEST_SIZE \
        (sizeof(struct virtio_flow_ctrl_hdr)       )

/*! Size of get packet processing stage  details of flow accelerator instance reply message*/
#define VIRTIO_FLOW_GET_PROC_STAGE_ACCEL_REPLY_SIZE \
        (sizeof(struct virtio_flow_ctrl_hdr)+    \
         sizeof(struct virtio_flow_proc_stage_info_reply)       )

/*! Size of add flow entry into packet processing stage of flow accelerator instance message*/
#define VIRTIO_FLOW_ADD_ENTRY_PROC_STAGE_ACCEL_SIZE \
        (sizeof(struct virtio_flow_ctrl_hdr)+    \
         sizeof(struct virtio_flow_add_entry_to_proc_stage)+   \
         sizeof(struct virtio_flow_ctrl_result)       )

/*! Size of modify flow of packet processing stage in flow accelerator instance message*/
#define VIRTIO_FLOW_MODIFY_ENTRY_PROC_STAGE_ACCEL_SIZE \
        (sizeof(struct virtio_flow_ctrl_hdr)+    \
         sizeof(struct virtio_flow_modify_entry_of_proc_stage)+   \
         sizeof(struct virtio_flow_ctrl_result)       )

/*! Size of delete flow from packet processing stage in flow accelerator instance message*/
#define VIRTIO_FLOW_DELETE_ENTRY_PROC_STAGE_ACCEL_SIZE \
        (sizeof(struct virtio_flow_ctrl_hdr)+    \
         sizeof(struct virtio_flow_delete_entry_from_proc_stage)+   \
         sizeof(struct virtio_flow_ctrl_result)       )

/*! Size of get flow enries packet processing stage  details of flow accelerator instance reply message*/
#define VIRTIO_FLOW_GET_FLOW_ENTRIES_PROC_STAGE_ACCEL_REPLY_SIZE \
        (sizeof(struct virtio_flow_ctrl_hdr)+    \
         sizeof(struct virtio_flow_proc_stage_entry_info_reply)    )

/*! Size of add object into packet proc stage of flow accelerator instance message*/
#define VIRTIO_FLOW_ADD_OBJ_TO_PROC_STAGE_ACCEL_SIZE \
        (sizeof(struct virtio_flow_ctrl_hdr)+    \
         sizeof(virtio_flow_stage_object_config_info_t)+   \
         sizeof(struct virtio_flow_ctrl_result)       )

/*! Size of modify object of packet proc stage of flow accelerator instance message*/
#define VIRTIO_FLOW_MODIFY_OBJ_OF_PROC_STAGE_ACCEL_SIZE \
        (sizeof(struct virtio_flow_ctrl_hdr)+    \
         sizeof(virtio_flow_stage_object_config_info_t)+   \
         sizeof(struct virtio_flow_ctrl_result)       )

/*! Size of modify object of packet proc stage of flow accelerator instance message*/
#define VIRTIO_FLOW_DELETE_OBJ_OF_PROC_STAGE_ACCEL_SIZE \
        (sizeof(struct virtio_flow_ctrl_hdr)+    \
         sizeof(struct virtio_flow_delete_object_config_info_t)+   \
         sizeof(struct virtio_flow_ctrl_result)       )

/*! Size of get object enries packet processing stage  details of flow accelerator instance reply message*/
#define VIRTIO_FLOW_GET_OBJ_ENTRIES_PROC_STAGE_ACCEL_REPLY_SIZE \
        (sizeof(struct virtio_flow_ctrl_hdr)+    \
         sizeof(struct virtio_flow_proc_stage_object_entry_info_reply)    )

/** ingroup VIRITO_FLOW_MESSAGE
*! Commands used to manage packet processing stage of flow accelerator instnace */
enum virtio_flow_ctrl_cmd_class_proc_stage_mgmt {

     /** Command to add packet processing stage to flow accelertor instance */
     VIRTIO_FLOW_ATTACH_PROC_STAGE_ACCEL = 1, 

     /** Message to get details of packet processing stages attached to 
      *  flow accelerator instance */
     VIRTIO_FLOW_GET_ACCEL_PROC_STAGES_INFO_REQUEST,

     /** Reply Message to  earlier 'VIRTIO_FLOW_GET_ACCEL_PROC_STAGES_INFO_REQUEST' 
      *  command */
     VIRTIO_FLOW_GET_ACCEL_PROC_STAGES_INFO_REPLY,

     /**  Message to add flow entry into table in packet processing stage */ 
     VIRTIO_FLOW_ADD_ENTRY_PROC_STAGE_ACCEL,

     /**  Message to modify flow entry of table in packet processing stage */ 
     VIRTIO_FLOW_MODIFY_ENTRY_PROC_STAGE_ACCEL,

     /**  Message to delete flow entry from table in packet processing stage */ 
     VIRTIO_FLOW_DELETE_ENTRY_PROC_STAGE_ACCEL,

     /** Message to get details of flow entries of proccessing stage */
     VIRTIO_FLOW_GET_ACCEL_ENTRIES_INFO_REQUEST,

     /** Reply Message to  earlier 'VIRTIO_FLOW_GET_ACCEL_ENTRIES_INFO_REQUEST' 
      *  command */
     VIRTIO_FLOW_GET_ACCEL_ENTRIES_INFO_REPLY,

     /**  Message to add object entry into packet processing stage */ 
     VIRTIO_FLOW_ADD_OBJ_ENTRY_PROC_STAGE_ACCEL,

     /**  Message to modify object entry of packet processing stage */ 
     VIRTIO_FLOW_MODIFY_OBJ_ENTRY_PROC_STAGE_ACCEL,

     /**  Message to delete object entry from packet processing stage */ 
     VIRTIO_FLOW_DELETE_OBJ_ENTRY_PROC_STAGE_ACCEL,

     /** Message to get details of object entries given type of proccessing stage */
     VIRTIO_FLOW_GET_ACCEL_OBJ_ENTRIES_PROC_STAGE_INFO_REQUEST,

     /** Reply Message to earlier 'VIRTIO_FLOW_GET_ACCEL_OBJ_ENTRIES_PROC_STAGE_INFO_REQUEST' 
      *  command */
     VIRTIO_FLOW_GET_ACCEL_OBJ_ENTRIES_PROC_STAGE_INFO_REPLY
};

/*! Size of add object into flow accelerator instance message*/
#define VIRTIO_FLOW_ADD_OBJ_TO_ACCEL_SIZE \
        (sizeof(struct virtio_flow_ctrl_hdr)+    \
         sizeof(virtio_flow_object_config_info_t)+   \
         sizeof(struct virtio_flow_ctrl_result)       )

/*! Size of modify object of flow accelerator instance message*/
#define VIRTIO_FLOW_MODIFY_OBJ_OF_ACCEL_SIZE \
        (sizeof(struct virtio_flow_ctrl_hdr)+    \
         sizeof(virtio_flow_stage_object_config_info_t)+   \
         sizeof(struct virtio_flow_ctrl_result)       )

/*! Size of modify object of flow accelerator instance message*/
#define VIRTIO_FLOW_DELETE_OBJ_OF_ACCEL_SIZE \
        (sizeof(struct virtio_flow_ctrl_hdr)+    \
         sizeof(struct virtio_flow_delete_object_config_info_t)+   \
         sizeof(struct virtio_flow_ctrl_result)       )

/*! Size of get object enries details of flow accelerator instance reply message*/
#define VIRTIO_FLOW_GET_OBJ_ENTRIES_ACCEL_REPLY_SIZE \
        (sizeof(struct virtio_flow_ctrl_hdr)+    \
         sizeof(struct virtio_flow_object_entry_info_reply)    )

/** ingroup VIRITO_FLOW_MESSAGE
*! Commands used to manage objects of flow accelerator instnace */
enum virtio_flow_ctrl_cmd_class_object_mgmt {

     /**  Message to add object entry into flow accelerator */ 
     VIRTIO_FLOW_ADD_OBJ_ENTRY_ACCEL,

     /**  Message to modify object entry of flow accelerator */ 
     VIRTIO_FLOW_MODIFY_OBJ_ENTRY_ACCEL,

     /**  Message to delete object entry from flow accelerator */ 
     VIRTIO_FLOW_DELETE_OBJ_ENTRY_ACCEL,

     /** Message to get details of object entries given type of flow accelerator */
     VIRTIO_FLOW_GET_ACCEL_OBJ_ENTRIES_INFO_REQUEST,

     /** Reply Message to earlier 'VIRTIO_FLOW_GET_ACCEL_OBJ_ENTRIES_INFO_REQUEST' 
      *  command */
     VIRTIO_FLOW_GET_ACCEL_OBJ_ENTRIES_INFO_REPLY
};

/*! 
 * \brief Build message containing command used to create flow accelerator instance  
 *
 * \param[in] in   -  Input arguments to build create flow accelerator instance message
 *
 * \param[out] len - Pointer Total length of the message including result data
 *
 * \param[out] msg - Message buffer
 *
 * \param[out] result_ptr - Offset in 'msg' where result data will be returned. In case 
 *                          of success, result contains flow accelerator instance handle
 *                          that will be used in subsequenet operations on the instance. 
 *
 * \returns VIRTIO_FLOW_SUCCESS upon success or VIRTIO_FLOW_FAILURE
 *
 * \ingroup VIRITO_FLOW_MESSAGE
 */
int32_t virtio_flow_msg_create_instance(
                       const g_flow_open_flow_accel_inargs_t in,
                       uint32_t *len, 
                       uint8_t **msg,
                       uint8_t **result_ptr);

/*! 
 * \brief Build message containing command to inform accelerator that application is ready  
 *
 * \param[in] accel_handle - Accelerator handle returned as part of create instance command result data  
 *
 * \param[out] len - Pointer Total length of the message 
 *
 * \param[out] msg - Message buffer
 *
 * \returns VIRTIO_FLOW_SUCCESS upon success or VIRTIO_FLOW_FAILURE
 *
 * \ingroup VIRITO_FLOW_MESSAGE
 */
int32_t virtio_flow_msg_instance_app_ready(
                       uint64_t accel_handle,
                       uint32_t *len,
                       uint8_t **msg);

/*! 
 * \brief Build message containing command to delete flow aceelerator instance  
 *
 * \param[in] accel_handle - Accelerator handle returned as part of create instance command result data  
 *
 * \param[out] len - Pointer to Total length of the message 
 *
 * \param[out] msg - Message buffer
 *
 * \returns VIRTIO_FLOW_SUCCESS upon success or VIRTIO_FLOW_FAILURE
 *
 * \ingroup VIRITO_FLOW_MESSAGE
 */
int32_t virtio_flow_msg_delete_instance(
                       uint64_t accel_handle,
                       uint32_t *len,
                       uint8_t **msg);

/*! 
 * \brief Build message containing command to add port flow aceelerator instance  
 *
 * \param[in] accel_handle - Accelerator handle returned as part of create instance command result data  
 *
 * \param[in] in   - Input arguments to build add port to flow accelerator instance message
 *
 * \param[out] len - Pointer to Total length of the message 
 *
 * \param[out] msg - Message buffer
 *
 * \param[out] result_ptr - Offset in 'msg' where result data will be returned. In case 
 *                          of error, result optionally contains error description string. 
 *
 * \returns VIRTIO_FLOW_SUCCESS upon success or VIRTIO_FLOW_FAILURE
 *
 * \ingroup VIRITO_FLOW_MESSAGE
 */
int32_t virtio_flow_msg_attach_port(
                       uint64_t accel_handle,
                       const struct g_flow_port_config_inargs in,
                       uint32_t *len,
                       uint8_t **msg,
                       uint8_t **result_ptr);

/*! 
 * \brief Build message containing command to get port details of flow aceelerator instance  
 *
 * \param[in] accel_handle - Accelerator handle returned as part of create instance command result data  
 *
 * \param[out] len - Pointer to Total length of the message 
 *
 * \param[out] msg - Message buffer
 *
 * \param[out] result_ptr - Offset in 'msg' where result data will be returned. In case 
 *                          of error, result optionally contains error description string. 
 *
 * \returns VIRTIO_FLOW_SUCCESS upon success or VIRTIO_FLOW_FAILURE
 *
 * \ingroup VIRITO_FLOW_MESSAGE
 */
int32_t virtio_flow_msg_get_port_info(
                       uint64_t accel_handle,
                       uint32_t *len,
                       uint8_t **msg,
                       uint8_t **result_ptr);

/*! 
 * \brief Build message containing command to add packet processing stage to flow aceelerator instance  
 *
 * \param[in] accel_handle - Accelerator handle returned as part of create instance command result data  
 *
 * \param[in] in   - Input arguments to build add packet processing stage to flow accelerator instance message
 *
 * \param[out] len - Pointer to Total length of the message 
 *
 * \param[out] msg - Message buffer
 *
 * \param[out] result_ptr - Offset in 'msg' where result data will be returned. In case 
 *                          of error, result optionally contains error description string. 
 *
 * \returns VIRTIO_FLOW_SUCCESS upon success or VIRTIO_FLOW_FAILURE
 *
 * \ingroup VIRITO_FLOW_MESSAGE
 */
int32_t virtio_flow_msg_attach_proc_stage(
                       uint64_t accel_handle,
                       const struct g_flow_stage_config_inargs in,
                       uint32_t *len,
                       uint8_t **msg,
                       uint8_t **result_ptr);

/*! 
 * \brief Build message containing command to get packet processing stages details of flow aceelerator instance  
 *
 * \param[in] accel_handle - Accelerator handle returned as part of create instance command result data  
 *
 * \param[out] len - Pointer to Total length of the message 
 *
 * \param[out] msg - Message buffer
 *
 * \param[out] result_ptr - Offset in 'msg' where result data will be returned. In case 
 *                          of error, result optionally contains error description string. 
 *
 * \returns VIRTIO_FLOW_SUCCESS upon success or VIRTIO_FLOW_FAILURE
 *
 * \ingroup VIRITO_FLOW_MESSAGE
 */
int32_t virtio_flow_msg_get_proce_stage_info(
                       uint64_t accel_handle,
                       uint32_t *len,
                       uint8_t **msg,
                       uint8_t **result_ptr);
/*! 
 * \brief Build message containing command to add flow to packet processing stage of flow aceelerator instance  
 *
 * \param[in] accel_handle - Accelerator handle returned as part of create instance command result data  
 *
 * \param[in] in   - Input arguments to build add flow entry into packet processing stage
 *
 * \param[out] len - Pointer to Total length of the message 
 *
 * \param[out] msg - Message buffer
 *
 * \param[out] result_ptr - Offset in 'msg' where result data will be returned. In case 
 *                          of error, result optionally contains error description string. 
 *
 * \returns VIRTIO_FLOW_SUCCESS upon success or VIRTIO_FLOW_FAILURE
 *
 * \ingroup VIRITO_FLOW_MESSAGE
 */
int32_t virtio_flow_msg_add_entry_proc_stage(
                       uint64_t accel_handle,
                       const struct g_flow_stage_add_n_mod_flow_entry_inargs in,
                       uint32_t *len,
                       uint8_t **msg,
                       uint8_t **result_ptr);

/*! 
 * \brief Build message containing command to modify flow to packet processing stage of flow aceelerator instance  
 *
 * \param[in] accel_handle - Accelerator handle returned as part of create instance command result data  
 *
 * \param[in] in   - Input arguments to build modify flow entry of packet processing stage
 *
 * \param[out] len - Pointer to Total length of the message 
 *
 * \param[out] msg - Message buffer
 *
 * \param[out] result_ptr - Offset in 'msg' where result data will be returned. In case 
 *                          of error, result optionally contains error description string. 
 *
 * \returns VIRTIO_FLOW_SUCCESS upon success or VIRTIO_FLOW_FAILURE
 *
 * \ingroup VIRITO_FLOW_MESSAGE
 */
int32_t virtio_flow_msg_modify_entry_proc_stage(
                       uint64_t accel_handle,
                       const struct g_flow_stage_add_n_mod_flow_entry_inargs in,
                       uint32_t *len,
                       uint8_t **msg,
                       uint8_t **result_ptr);
/*! 
 * \brief Build message containing command to delete flow from packet processing stage of flow aceelerator instance  
 *
 * \param[in] accel_handle - Accelerator handle returned as part of create instance command result data  
 *
 * \param[in] in   - Input arguments to build delete flow entry of packet processing stage
 *
 * \param[out] len - Pointer to Total length of the message 
 *
 * \param[out] msg - Message buffer
 *
 * \param[out] result_ptr - Offset in 'msg' where result data will be returned. In case 
 *                          of error, result optionally contains error description string. 
 *
 * \returns VIRTIO_FLOW_SUCCESS upon success or VIRTIO_FLOW_FAILURE
 *
 * \ingroup VIRITO_FLOW_MESSAGE
 */
int32_t virtio_flow_msg_delete_entry_proc_stage(
                       uint64_t accel_handle,
                       const struct g_flow_stage_del_flow_entires_inarg in,
                       uint32_t *len,
                       uint8_t **msg,
                       uint8_t **result_ptr);
/*! 
 * \brief Build message containing command to get flow entries of packet processing stages
 *
 * \param[in] accel_handle - Accelerator handle returned as part of create instance command result data  
 *
 * \param[out] len - Pointer to Total length of the message 
 *
 * \param[out] msg - Message buffer
 *
 * \param[out] result_ptr - Offset in 'msg' where result data will be returned. In case 
 *                          of error, result optionally contains error description string. 
 *
 * \returns VIRTIO_FLOW_SUCCESS upon success or VIRTIO_FLOW_FAILURE
 *
 * \ingroup VIRITO_FLOW_MESSAGE
 */
int32_t virtio_flow_msg_get_entries_info(
                       uint64_t accel_handle,
                       uint32_t *len,
                       uint8_t **msg,
                       uint8_t **result_ptr);
/*! 
 * \brief Build message containing command to add object to given type of processing stage
 *
 * \param[in] accel_handle - Accelerator handle returned as part of create instance command result data  
 *
 * \param[in] in   - Input arguments to build add object entry into packet processing stage
 *
 * \param[out] len - Pointer to Total length of the message 
 *
 * \param[out] msg - Message buffer
 *
 * \param[out] result_ptr - Offset in 'msg' where result data will be returned. In case 
 *                          of error, result optionally contains error description string. 
 *
 * \returns VIRTIO_FLOW_SUCCESS upon success or VIRTIO_FLOW_FAILURE
 *
 * \ingroup VIRITO_FLOW_MESSAGE
 */
int32_t virtio_flow_msg_add_obj_entry_proc_stage(
                       uint64_t accel_handle,
                       const struct g_flow_stage_object_entry_inarg in,
                       uint32_t *len,
                       uint8_t **msg,
                       uint8_t **result_ptr);

/*! 
 * \brief Build message containing command to modify object of given type of processing stage
 *
 * \param[in] accel_handle - Accelerator handle returned as part of create instance command result data  
 *
 * \param[in] in   - Input arguments to build modify object entry of packet processing stage
 *
 * \param[out] len - Pointer to Total length of the message 
 *
 * \param[out] msg - Message buffer
 *
 * \param[out] result_ptr - Offset in 'msg' where result data will be returned. In case 
 *                          of error, result optionally contains error description string. 
 *
 * \returns VIRTIO_FLOW_SUCCESS upon success or VIRTIO_FLOW_FAILURE
 *
 * \ingroup VIRITO_FLOW_MESSAGE
 */
int32_t virtio_flow_msg_modify_obj_entry_proc_stage(
                       uint64_t accel_handle,
                       const struct g_flow_stage_object_entry_inarg in,
                       uint32_t *len,
                       uint8_t **msg,
                       uint8_t **result_ptr);
/*! 
 * \brief Build message containing command to delete object of given type from packet processing stage
 *
 * \param[in] accel_handle - Accelerator handle returned as part of create instance command result data  
 *
 * \param[in] stage_id  - Packet processing stage from which deleting object(s)
 *
 * \param[in] type - Type of object list from which deleting object(s)
 *
 * \param[in] id - ID of object to delete.
 *
 * \param[out] len - Pointer to Total length of the message 
 *
 * \param[out] msg - Message buffer
 *
 * \param[out] result_ptr - Offset in 'msg' where result data will be returned. In case 
 *                          of error, result optionally contains error description string. 
 *
 * \returns VIRTIO_FLOW_SUCCESS upon success or VIRTIO_FLOW_FAILURE
 *
 * \ingroup VIRITO_FLOW_MESSAGE
 */
int32_t virtio_flow_msg_delete_obj_entry_proc_stage(
                       uint64_t accel_handle,
                       uint8_t stage_id,
                       enum g_flow_objects type,
                       uint32_t id,
                       uint32_t *len,
                       uint8_t **msg,
                       uint8_t **result_ptr);
/*! 
 * \brief Build message containing command to get object entries of packet processing stages
 *
 * \param[in] accel_handle - Accelerator handle returned as part of create instance command result data  
 *
 * \param[in] in   - Input arguments to build message get object entries of packet processing stage
 *
 * \param[out] len - Pointer to Total length of the message 
 *
 * \param[out] msg - Message buffer
 *
 * \param[out] result_ptr - Offset in 'msg' where result data will be returned. In case 
 *                          of error, result optionally contains error description string. 
 *
 * \returns VIRTIO_FLOW_SUCCESS upon success or VIRTIO_FLOW_FAILURE
 *
 * \ingroup VIRITO_FLOW_MESSAGE
 */
int32_t virtio_flow_msg_get_obj_entries_proc_stage(
                       uint64_t accel_handle,
                       const struct g_flow_get_stage_object_inargs in,
                       uint32_t *len,
                       uint8_t **msg,
                       uint8_t **result_ptr);
/*! 
 * \brief Build message containing command to add object to given type of flow accelrator 
 *
 * \param[in] accel_handle - Accelerator handle returned as part of create instance command result data  
 *
 * \param[in] in   - Input arguments to build add object entry into flow accelrator 
 *
 * \param[out] len - Pointer to Total length of the message 
 *
 * \param[out] msg - Message buffer
 *
 * \param[out] result_ptr - Offset in 'msg' where result data will be returned. In case 
 *                          of error, result optionally contains error description string. 
 *
 * \returns VIRTIO_FLOW_SUCCESS upon success or VIRTIO_FLOW_FAILURE
 *
 * \ingroup VIRITO_FLOW_MESSAGE
 */
int32_t virtio_flow_msg_add_obj_entry(
                       uint64_t accel_handle,
                       const struct g_flow_object_entry_inarg in,
                       uint32_t *len,
                       uint8_t **msg,
                       uint8_t **result_ptr);

/*! 
 * \brief Build message containing command to modify object of given flow accelerator
 *
 * \param[in] accel_handle - Accelerator handle returned as part of create instance command result data  
 *
 * \param[in] in   - Input arguments to build modify object entry of flow accelerator
 *
 * \param[out] len - Pointer to Total length of the message 
 *
 * \param[out] msg - Message buffer
 *
 * \param[out] result_ptr - Offset in 'msg' where result data will be returned. In case 
 *                          of error, result optionally contains error description string. 
 *
 * \returns VIRTIO_FLOW_SUCCESS upon success or VIRTIO_FLOW_FAILURE
 *
 * \ingroup VIRITO_FLOW_MESSAGE
 */
int32_t virtio_flow_msg_modify_obj_entry(
                       uint64_t accel_handle,
                       const struct g_flow_object_entry_inarg in,
                       uint32_t *len,
                       uint8_t **msg,
                       uint8_t **result_ptr);

/*! 
 * \brief Build message containing command to delete object of given type from flow accelerator 
 *
 * \param[in] accel_handle - Accelerator handle returned as part of create instance command result data  
 *
 * \param[in] type - Type of object list from which deleting object(s)
 *
 * \param[in] id - ID of object to delete.
 *
 * \param[out] len - Pointer to Total length of the message 
 *
 * \param[out] msg - Message buffer
 *
 * \param[out] result_ptr - Offset in 'msg' where result data will be returned. In case 
 *                          of error, result optionally contains error description string. 
 *
 * \returns VIRTIO_FLOW_SUCCESS upon success or VIRTIO_FLOW_FAILURE
 *
 * \ingroup VIRITO_FLOW_MESSAGE
 */
int32_t virtio_flow_msg_delete_obj_entry(
                       uint64_t accel_handle,
                       uint8_t stage_id,
                       enum g_flow_objects type,
                       uint32_t id,
                       uint32_t *len,
                       uint8_t **msg,
                       uint8_t **result_ptr);
/*! 
 * \brief Build message containing command to get object entries of flow accelerator
 *
 * \param[in] accel_handle - Accelerator handle returned as part of create instance command result data  
 *
 * \param[in] in   - Input arguments to build message get object entries of flow accelerator
 *
 * \param[out] len - Pointer to Total length of the message 
 *
 * \param[out] msg - Message buffer
 *
 * \param[out] result_ptr - Offset in 'msg' where result data will be returned. In case 
 *                          of error, result optionally contains error description string. 
 *
 * \returns VIRTIO_FLOW_SUCCESS upon success or VIRTIO_FLOW_FAILURE
 *
 * \ingroup VIRITO_FLOW_MESSAGE
 */
int32_t virtio_flow_msg_get_obj_entries(
                       uint64_t accel_handle,
                       const struct g_flow_get_object_inargs in,
                       uint32_t *len,
                       uint8_t **msg,
                       uint8_t **result_ptr);


#endif /*_VIRTIO_FLOW_MSG_H*/
