/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the Apache License, Version 2.0  (the "License"); you may not use this file
 * except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include <inttypes.h>
#include "bstrlib.h"

#include "hashtable.h"
#include "log.h"
#include "msc.h"
#include "3gpp_requirements_36.413.h"
#include "assertions.h"
#include "mme_api.h"
#include "conversions.h"
#include "intertask_interface.h"
#include "timer.h"
#include "dynamic_memory_check.h"
#include "bstrlib.h"
#include "mme_config.h"
#include "s1ap_common.h"
#include "s1ap_ies_defs.h"
#include "s1ap_mme_encoder.h"
#include "s1ap_mme_nas_procedures.h"
#include "s1ap_mme_itti_messaging.h"
#include "s1ap_mme.h"
#include "s1ap_mme_ta.h"
#include "s1ap_mme_handlers.h"
#include "s1ap_handover_signaling_handler.h"

static int s1ap_mme_generate_s1_path_switch_request_failure (
    const sctp_assoc_id_t assoc_id,
    const S1ap_Cause_PR cause_type,
    const long cause_value,
    const mme_ue_s1ap_id_t mme_ue_s1ap_id,
    const enb_ue_s1ap_id_t enb_ue_s1ap_id);

static int s1ap_mme_generate_s1_path_switch_request_ack (
    const sctp_assoc_id_t assoc_id,
    const mme_ue_s1ap_id_t mme_ue_s1ap_id,
    const enb_ue_s1ap_id_t enb_ue_s1ap_id,
    const S1ap_SecurityContext_t security_context);


////////////////////////////////////////////////////////////////////////////////
//************************ Handover signalling *******************************//
////////////////////////////////////////////////////////////////////////////////

//------------------------------------------------------------------------------
int
s1ap_mme_handle_path_switch_request (
    __attribute__((unused)) const sctp_assoc_id_t assoc_id,
    __attribute__((unused)) const sctp_stream_id_t stream,
    struct s1ap_message_s *message)
{
  S1ap_PathSwitchRequestIEs_t            *pathSwitchRequest_p = NULL;
  ue_description_t                       *ue_ref_p = NULL;
  enb_ue_s1ap_id_t                        enb_ue_s1ap_id = 0;
  S1ap_E_RABToBeSwitchedDLItem_t  	     *e_RABToBeSwitchedDLItem_p = NULL;
  MessageDef                             *message_p = NULL;
  int                                     rc = RETURNerror;
  
  OAILOG_FUNC_IN (LOG_S1AP);
  pathSwitchRequest_p = &message->msg.s1ap_PathSwitchRequestIEs;
  // eNB UE S1AP ID is limited to 24 bits
  enb_ue_s1ap_id = (enb_ue_s1ap_id_t) (pathSwitchRequest_p->eNB_UE_S1AP_ID & ENB_UE_S1AP_ID_MASK);
  OAILOG_DEBUG (LOG_S1AP, "Path Switch Request message received from eNB UE S1AP ID: " ENB_UE_S1AP_ID_FMT " assoc_id : %u\n", enb_ue_s1ap_id, assoc_id);

  if ((ue_ref_p = s1ap_is_ue_mme_id_in_list (pathSwitchRequest_p->sourceMME_UE_S1AP_ID)) == NULL) {
    /*
     * The MME UE S1AP ID provided by eNB doesn't point to any valid UE.
     * * * * MME replies with a PATH SWITCH REQUEST FAILURE message and start operation
     * * * * as described in TS 36.413 [11].
     */
    OAILOG_ERROR (LOG_S1AP, "Rejecting s1 spath switch request. Can not process the request, MME UE S1AP ID provided by eNB doesn't point to any valid UE. \n");
    rc = s1ap_mme_generate_s1_path_switch_request_failure(assoc_id, S1ap_Cause_PR_radioNetwork, S1ap_CauseRadioNetwork_unknown_mme_ue_s1ap_id, pathSwitchRequest_p->sourceMME_UE_S1AP_ID, enb_ue_s1ap_id );
   OAILOG_FUNC_RETURN (LOG_S1AP, rc);
  } else {
    s1ap_update_ue (ue_ref_p, assoc_id, enb_ue_s1ap_id);
    if (pathSwitchRequest_p->e_RABToBeSwitchedDLList.s1ap_E_RABToBeSwitchedDLItem.count != 1) {
      OAILOG_DEBUG (LOG_S1AP, "E-RAB update has failed\n");
      OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
    }
    message_p = itti_alloc_new_message (TASK_S1AP, MME_APP_PATH_SWITCH_REQUEST);
    AssertFatal (message_p != NULL, "itti_alloc_new_message Failed");

    MME_APP_PATH_SWITCH_REQUEST (message_p).ue_id = ue_ref_p->mme_ue_s1ap_id; 
    MME_APP_PATH_SWITCH_REQUEST (message_p).enb_ue_s1ap_id = enb_ue_s1ap_id;
	  MME_APP_PATH_SWITCH_REQUEST (message_p).assoc_id = assoc_id;
    MME_APP_PATH_SWITCH_REQUEST (message_p).no_of_e_rabs = pathSwitchRequest_p->e_RABToBeSwitchedDLList.s1ap_E_RABToBeSwitchedDLItem.count;
    for (int item = 0; item < pathSwitchRequest_p->e_RABToBeSwitchedDLList.s1ap_E_RABToBeSwitchedDLItem.count; item++) {
     /*
      * Bad, very bad cast...
      */
      e_RABToBeSwitchedDLItem_p = (S1ap_E_RABSetupItemCtxtSURes_t *)
        pathSwitchRequest_p->e_RABToBeSwitchedDLList.s1ap_E_RABToBeSwitchedDLItem.array[item];
      MME_APP_PATH_SWITCH_REQUEST (message_p).e_rab_id[item] = e_RABToBeSwitchedDLItem_p->e_RAB_ID;
      MME_APP_PATH_SWITCH_REQUEST (message_p).gtp_teid[item] = htonl (*((uint32_t *) e_RABToBeSwitchedDLItem_p->gTP_TEID.buf));
      MME_APP_PATH_SWITCH_REQUEST (message_p).transport_layer_address[item] = 
      blk2bstr(e_RABToBeSwitchedDLItem_p->transportLayerAddress.buf, e_RABToBeSwitchedDLItem_p->transportLayerAddress.size);
    }
	  rc = itti_send_msg_to_task (TASK_MME_APP, INSTANCE_DEFAULT, message_p);
    OAILOG_FUNC_RETURN (LOG_S1AP, rc);
  }
  OAILOG_FUNC_RETURN (LOG_S1AP, RETURNok);
}

//------------------------------------------------------------------------------
int
s1ap_handle_mme_path_switch_request_ack (
        const itti_s1ap_enb_path_switch_request_ack_t *itti_s1ap_enb_path_switch_request_ack_p)
{
  sctp_assoc_id_t assoc_id;
  mme_ue_s1ap_id_t mme_ue_s1ap_id;
  enb_ue_s1ap_id_t enb_ue_s1ap_id;
  S1ap_SecurityContext_t security_context;

  OAILOG_FUNC_IN (LOG_S1AP);
  OAILOG_DEBUG (LOG_S1AP, "Path Switch Request ACK message received from MME \n");
  assoc_id = itti_s1ap_enb_path_switch_request_ack_p->assoc_id;
  mme_ue_s1ap_id = itti_s1ap_enb_path_switch_request_ack_p->ue_id;
  enb_ue_s1ap_id = itti_s1ap_enb_path_switch_request_ack_p->enb_ue_s1ap_id;
  security_context.nextHopChainingCount = itti_s1ap_enb_path_switch_request_ack_p->ncc;
  security_context.nextHopParameter.buf = itti_s1ap_enb_path_switch_request_ack_p->nh;
  security_context.nextHopParameter.size = AUTH_NH_SIZE;
  
  s1ap_mme_generate_s1_path_switch_request_ack (assoc_id, mme_ue_s1ap_id, enb_ue_s1ap_id, security_context);
  OAILOG_FUNC_RETURN (LOG_S1AP, RETURNok);
}

//------------------------------------------------------------------------------
int
s1ap_handle_mme_path_switch_request_failure (
        const itti_s1ap_enb_path_switch_request_failure_t *itti_s1ap_enb_path_switch_request_failure_p)
{
  sctp_assoc_id_t assoc_id;
  S1ap_Cause_PR cause_type;
  long cause_value;
  mme_ue_s1ap_id_t mme_ue_s1ap_id;
  enb_ue_s1ap_id_t enb_ue_s1ap_id;

  OAILOG_FUNC_IN (LOG_S1AP);
  OAILOG_DEBUG (LOG_S1AP, "Path Switch Request FAILURE message received from MME \n");
  assoc_id = itti_s1ap_enb_path_switch_request_failure_p->assoc_id;
  mme_ue_s1ap_id = itti_s1ap_enb_path_switch_request_failure_p->ue_id;
  enb_ue_s1ap_id = itti_s1ap_enb_path_switch_request_failure_p->enb_ue_s1ap_id;
  cause_type = itti_s1ap_enb_path_switch_request_failure_p->cause_type;
  cause_value = itti_s1ap_enb_path_switch_request_failure_p->cause_value;

  s1ap_mme_generate_s1_path_switch_request_failure (assoc_id, cause_type, cause_value, mme_ue_s1ap_id, enb_ue_s1ap_id);
  OAILOG_FUNC_RETURN (LOG_S1AP, RETURNok);
}


//------------------------------------------------------------------------------
int
s1ap_mme_generate_s1_path_switch_request_failure (
    const sctp_assoc_id_t assoc_id,
    const S1ap_Cause_PR cause_type,
    const long cause_value,
    const mme_ue_s1ap_id_t mme_ue_s1ap_id,
    const enb_ue_s1ap_id_t enb_ue_s1ap_id)
{
  uint8_t                                *buffer_p = 0;
  uint32_t                                length = 0;
  s1ap_message                            message = { 0 };
  S1ap_PathSwitchRequestFailureIEs_t     *s1_path_switch_request_failure_p = NULL;
  int                                     rc = RETURNok;

  OAILOG_FUNC_IN (LOG_S1AP);
  s1_path_switch_request_failure_p = &message.msg.s1ap_PathSwitchRequestFailureIEs;
  message.procedureCode = S1ap_ProcedureCode_id_PathSwitchRequest;
  message.direction = S1AP_PDU_PR_unsuccessfulOutcome;


  s1_path_switch_request_failure_p->mme_ue_s1ap_id = mme_ue_s1ap_id;
  s1_path_switch_request_failure_p->eNB_UE_S1AP_ID = enb_ue_s1ap_id;
  s1ap_mme_set_cause (&s1_path_switch_request_failure_p->cause, cause_type, cause_value);

  if (s1ap_mme_encode_pdu (&message, &buffer_p, &length) < 0) {
    OAILOG_ERROR (LOG_S1AP, "Failed to encode s1 path switch request failure\n");
    OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
  }

  MSC_LOG_TX_MESSAGE (MSC_S1AP_MME, MSC_S1AP_ENB, NULL, 0, "0 S1apPathSwitchRequest/unsuccessfulOutcome  assoc_id %u cause %u value %u", assoc_id, cause_type, cause_value);
  bstring b = blk2bstr(buffer_p, length);
  free(buffer_p);
  rc =  s1ap_mme_itti_send_sctp_request (&b, assoc_id, 0, INVALID_MME_UE_S1AP_ID);
  OAILOG_FUNC_RETURN (LOG_S1AP, rc);
}

//------------------------------------------------------------------------------
int
s1ap_mme_generate_s1_path_switch_request_ack (
    const sctp_assoc_id_t assoc_id,
    const mme_ue_s1ap_id_t mme_ue_s1ap_id,
    const enb_ue_s1ap_id_t enb_ue_s1ap_id,
    const S1ap_SecurityContext_t security_context)
{
  uint8_t                                   *buffer_p = 0;
  uint32_t                                  length = 0;
  s1ap_message                              message = { 0 };
  S1ap_PathSwitchRequestAcknowledgeIEs_t    *s1_path_switch_request_ack_p = NULL;
  int                                       rc = RETURNok;

  OAILOG_FUNC_IN (LOG_S1AP);
  s1_path_switch_request_ack_p = &message.msg.s1ap_PathSwitchRequestAcknowledgeIEs;
  message.procedureCode = S1ap_ProcedureCode_id_PathSwitchRequest;
  message.direction = S1AP_PDU_PR_successfulOutcome;

  //Mandatory fields
  s1_path_switch_request_ack_p->securityContext.nextHopChainingCount = security_context.nextHopChainingCount;
  s1_path_switch_request_ack_p->securityContext.nextHopParameter = security_context.nextHopParameter;
  s1_path_switch_request_ack_p->securityContext.iE_Extensions = NULL;
  s1_path_switch_request_ack_p->mme_ue_s1ap_id = mme_ue_s1ap_id;
  s1_path_switch_request_ack_p->eNB_UE_S1AP_ID = enb_ue_s1ap_id;

  if (s1ap_mme_encode_pdu (&message, &buffer_p, &length) < 0) {
    OAILOG_ERROR (LOG_S1AP, "Failed to encode s1 path switch request acknowledge\n");
    OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
  }

  MSC_LOG_TX_MESSAGE (MSC_S1AP_MME, MSC_S1AP_ENB, NULL, 0, "0 S1apPathSwithRequest/successfulOutcome  assoc_id %u", assoc_id);
  bstring b = blk2bstr(buffer_p, length);
  free(buffer_p);
  rc =  s1ap_mme_itti_send_sctp_request (&b, assoc_id, 0, INVALID_MME_UE_S1AP_ID);
  OAILOG_FUNC_RETURN (LOG_S1AP, rc);
}

//------------------------------------------------------------------------------
int
s1ap_mme_encode_s1pathswitchrequestfailure (
  s1ap_message * message_p,
  uint8_t ** buffer,
  uint32_t * length)
{
  S1ap_PathSwitchRequestFailure_t                   s1PathSwitchRequestFailure;
  S1ap_PathSwitchRequestFailure_t                  *s1PathSwitchRequestFailure_p = &s1PathSwitchRequestFailure;

  memset (s1PathSwitchRequestFailure_p, 0, sizeof (S1ap_PathSwitchRequestFailure_t));

  if (s1ap_encode_s1ap_pathswitchrequestfailureies (s1PathSwitchRequestFailure_p,  &message_p->msg.s1ap_PathSwitchRequestFailureIEs) < 0) {
    return -1;
  }

  return s1ap_generate_unsuccessfull_outcome (buffer, length, S1ap_ProcedureCode_id_PathSwitchRequest, message_p->criticality, &asn_DEF_S1ap_PathSwitchRequestFailure, s1PathSwitchRequestFailure_p);
}

//------------------------------------------------------------------------------
int
s1ap_mme_encode_s1pathswitchrequestack (
  s1ap_message * message_p,
  uint8_t ** buffer,
  uint32_t * length)
{
  S1ap_PathSwitchRequestAcknowledge_t                   s1PathSwitchRequestAck;
  S1ap_PathSwitchRequestAcknowledge_t                  *s1PathSwitchRequestAck_p = &s1PathSwitchRequestAck;

  memset (s1PathSwitchRequestAck_p, 0, sizeof (S1ap_PathSwitchRequestAcknowledge_t));

  if (s1ap_encode_s1ap_pathswitchrequestacknowledgeies (s1PathSwitchRequestAck_p,  &message_p->msg.s1ap_PathSwitchRequestAcknowledgeIEs) < 0) {
    return -1;
  }

  return s1ap_generate_successfull_outcome (buffer, length, S1ap_ProcedureCode_id_PathSwitchRequest, message_p->criticality, &asn_DEF_S1ap_PathSwitchRequestAcknowledge, s1PathSwitchRequestAck_p);
}



// Note this file can have functions that are to be called in MME module to process 
