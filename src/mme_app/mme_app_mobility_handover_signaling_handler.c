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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

#include "bstrlib.h"

#include "dynamic_memory_check.h"
#include "log.h"
#include "msc.h"
#include "assertions.h"
#include "conversions.h"
#include "common_types.h"
#include "intertask_interface.h"
#include "mme_config.h"
#include "mme_app_extern.h"
#include "mme_app_ue_context.h"
#include "mme_app_defs.h"
#include "mme_app_apn_selection.h"
#include "mme_app_pdn_context.h"
#include "mme_app_sgw_selection.h"
#include "mme_app_bearer_context.h"
#include "bstrlib.h"
#include "sgw_ie_defs.h"
#include "common_defs.h"
#include "gcc_diag.h"
#include "mme_app_itti_messaging.h"
#include "mme_app_procedures.h"
#include "mme_app_statistics.h"
#include "timer.h"
#include "nas_proc.h"
#include "security_types.h"
#include "secu_defs.h"
#include "mme_app_handover_signaling_handler.h"

//------------------------------------------------------------------------------
void
mme_app_handle_path_switch_request (
  itti_mme_app_path_switch_request_t * const path_switch_request_pP)
{
  struct ue_mm_context_s                 *ue_context_p = NULL;
  MessageDef                             *message_p = NULL;
  
  OAILOG_FUNC_IN (LOG_MME_APP);
  OAILOG_DEBUG (LOG_MME_APP, "Received MME_APP_PATH_SWITCH_REQUEST from S1AP\n");
  ue_context_p = mme_ue_context_exists_mme_ue_s1ap_id (&mme_app_desc.mme_ue_contexts, path_switch_request_pP->ue_id);

  if (ue_context_p == NULL) {
    OAILOG_DEBUG (LOG_MME_APP, "We didn't find this mme_ue_s1ap_id in list of UE: " MME_UE_S1AP_ID_FMT "\n", path_switch_request_pP->ue_id);
    MSC_LOG_EVENT (MSC_MMEAPP_MME, " MME_APP_PATH_SWITCH_REQUEST Unknown ue %u", path_switch_request_pP->ue_id);
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }
  //Update UE context
  ue_context_p->enb_ue_s1ap_id = path_switch_request_pP->enb_ue_s1ap_id; 
  ue_context_p->sctp_assoc_id_key = path_switch_request_pP->assoc_id;
  message_p = itti_alloc_new_message (TASK_MME_APP, S11_MODIFY_BEARER_REQUEST);
  AssertFatal (message_p , "itti_alloc_new_message Failed");
  itti_s11_modify_bearer_request_t *s11_modify_bearer_request = &message_p->ittiMsg.s11_modify_bearer_request;
  s11_modify_bearer_request->local_teid = ue_context_p->mme_teid_s11;
  /*
   * Delay Value in integer multiples of 50 millisecs, or zero
   */
  s11_modify_bearer_request->delay_dl_packet_notif_req = 0; 

  for (int item = 0; item < path_switch_request_pP->no_of_e_rabs; item++) {
    s11_modify_bearer_request->bearer_contexts_to_be_modified.bearer_contexts[item].eps_bearer_id     = path_switch_request_pP->e_rab_id[item];
    s11_modify_bearer_request->bearer_contexts_to_be_modified.bearer_contexts[item].s1_eNB_fteid.teid = path_switch_request_pP->gtp_teid[item];
    s11_modify_bearer_request->bearer_contexts_to_be_modified.bearer_contexts[item].s1_eNB_fteid.interface_type    = S1_U_ENODEB_GTP_U;

    if (!item) {
      ebi_t             ebi = path_switch_request_pP->e_rab_id[item];
      pdn_cid_t         cid = ue_context_p->bearer_contexts[EBI_TO_INDEX(ebi)]->pdn_cx_id;
      pdn_context_t    *pdn_context = ue_context_p->pdn_contexts[cid];

      s11_modify_bearer_request->peer_ip = pdn_context->s_gw_address_s11_s4.address.ipv4_address;
      s11_modify_bearer_request->teid    = pdn_context->s_gw_teid_s11_s4;
    }
    if (4 == blength(path_switch_request_pP->transport_layer_address[item])) {
      s11_modify_bearer_request->bearer_contexts_to_be_modified.bearer_contexts[item].s1_eNB_fteid.ipv4         = 1;
      memcpy(&s11_modify_bearer_request->bearer_contexts_to_be_modified.bearer_contexts[item].s1_eNB_fteid.ipv4_address,
          path_switch_request_pP->transport_layer_address[item]->data, blength(path_switch_request_pP->transport_layer_address[item]));
    } else if (16 == blength(path_switch_request_pP->transport_layer_address[item])) {
      s11_modify_bearer_request->bearer_contexts_to_be_modified.bearer_contexts[item].s1_eNB_fteid.ipv6         = 1;
      memcpy(&s11_modify_bearer_request->bearer_contexts_to_be_modified.bearer_contexts[item].s1_eNB_fteid.ipv6_address,
          path_switch_request_pP->transport_layer_address[item]->data,
          blength(path_switch_request_pP->transport_layer_address[item]));
    } else {
      AssertFatal(0, "TODO IP address %d bytes", blength(path_switch_request_pP->transport_layer_address[item]));
    }
    bdestroy_wrapper (&path_switch_request_pP->transport_layer_address[item]);
  }
  s11_modify_bearer_request->bearer_contexts_to_be_modified.num_bearer_context = path_switch_request_pP->no_of_e_rabs;

  s11_modify_bearer_request->bearer_contexts_to_be_removed.num_bearer_context = 0;

  s11_modify_bearer_request->mme_fq_csid.node_id_type = GLOBAL_UNICAST_IPv4; // TODO
  s11_modify_bearer_request->mme_fq_csid.csid = 0;   // TODO ...
  memset(&s11_modify_bearer_request->indication_flags, 0, sizeof(s11_modify_bearer_request->indication_flags));   // TODO
  s11_modify_bearer_request->rat_type = RAT_EUTRAN;
  /*
   * S11 stack specific parameter. Not used in standalone epc mode
   */
  s11_modify_bearer_request->trxn = NULL;
  MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME,  MSC_S11_MME ,
                      NULL, 0, "0 S11_MODIFY_BEARER_REQUEST teid %u ebi %u", s11_modify_bearer_request->teid,
                      s11_modify_bearer_request->bearer_contexts_to_be_modified.bearer_contexts[0].eps_bearer_id);
  itti_send_msg_to_task (TASK_S11, INSTANCE_DEFAULT, message_p);
  ue_context_p->ue_context_current_proc = X2_HO_PROC;
  unlock_ue_contexts(ue_context_p);
  OAILOG_FUNC_OUT (LOG_MME_APP);
}


//------------------------------------------------------------------------------
int
mme_app_handle_modify_bearer_resp_during_ho (
        itti_s11_modify_bearer_response_t * const modify_bearer_response_pP)
{

  struct ue_mm_context_s     *ue_context_p = NULL;
  MessageDef                 *message_p = NULL;
  int                        rc = RETURNerror;
  
  OAILOG_FUNC_IN (LOG_MME_APP);
  OAILOG_DEBUG (LOG_MME_APP, "Received MODIFIED BEARER RESPONSE from S11 during a x2 HO procedure\n");
  ue_context_p = mme_ue_context_exists_s11_teid (&mme_app_desc.mme_ue_contexts, modify_bearer_response_pP->teid);

  if (ue_context_p == NULL) {
    MSC_LOG_RX_DISCARDED_MESSAGE (MSC_MMEAPP_MME, MSC_S11_MME, NULL, 0, "0 MODIFY_BEARER_RESPONSE local S11 teid " TEID_FMT " ",
      modify_bearer_response_pP->teid);
    OAILOG_DEBUG (LOG_MME_APP, "We didn't find this teid in list of UE: %08x\n", modify_bearer_response_pP->teid);
    OAILOG_FUNC_RETURN (LOG_MME_APP, rc);
  }
  if (modify_bearer_response_pP->cause.cause_value != REQUEST_ACCEPTED){
    
    // Send PATH_SWITCH_REQUEST_FAILURE message to S1AP layer
    itti_s1ap_enb_path_switch_request_failure_t *s1ap_enb_path_switch_request_failure;
    message_p = itti_alloc_new_message (TASK_S1AP, S1AP_ENB_PATH_SWITCH_REQUEST_FAILURE);
    AssertFatal (message_p , "itti_alloc_new_message Failed");
    s1ap_enb_path_switch_request_failure = &message_p->ittiMsg.s1ap_enb_path_switch_request_failure;
    s1ap_enb_path_switch_request_failure->assoc_id = ue_context_p->sctp_assoc_id_key;
    s1ap_enb_path_switch_request_failure->ue_id = ue_context_p->mme_ue_s1ap_id;
    s1ap_enb_path_switch_request_failure->enb_ue_s1ap_id = ue_context_p->enb_ue_s1ap_id;
    s1ap_enb_path_switch_request_failure->cause_type = S1ap_Cause_PR_misc;
    s1ap_enb_path_switch_request_failure->cause_value = S1ap_CauseMisc_unspecified;
    rc = itti_send_msg_to_task (TASK_S1AP, INSTANCE_DEFAULT, message_p);
    unlock_ue_contexts(ue_context_p);
    OAILOG_FUNC_RETURN (LOG_MME_APP, rc);
  }
  // Send SECURITY_CONTEXT_REQ message to AS layer
  emm_context_t                          *ue_nas_ctx = NULL;
    
  ue_nas_ctx = emm_context_get (&_emm_data, ue_context_p->mme_ue_s1ap_id);
  if (ue_nas_ctx) {
    uint8_t                 tmp[32];
    ue_nas_ctx->_as_security.ncc = (ue_nas_ctx->_as_security.ncc + 1) % 7;
    memcpy ((uint8_t *) tmp, ue_nas_ctx->_as_security.nh, AUTH_NH_SIZE);
    derive_nh (ue_nas_ctx->_vector[ue_nas_ctx->_security.vector_index].kasme, (uint8_t *)tmp, ue_nas_ctx->_as_security.nh);

    //Send PATH_SWITCH_REQUEST_ACK message to S1AP layer
    itti_s1ap_enb_path_switch_request_ack_t *s1ap_enb_path_switch_request_ack;
    message_p = itti_alloc_new_message (TASK_S1AP, S1AP_ENB_PATH_SWITCH_REQUEST_ACK);
    AssertFatal (message_p , "itti_alloc_new_message Failed");
    s1ap_enb_path_switch_request_ack = &message_p->ittiMsg.s1ap_enb_path_switch_request_ack;
    s1ap_enb_path_switch_request_ack->assoc_id = ue_context_p->sctp_assoc_id_key;
    s1ap_enb_path_switch_request_ack->ue_id = ue_context_p->mme_ue_s1ap_id;
    s1ap_enb_path_switch_request_ack->enb_ue_s1ap_id = ue_context_p->enb_ue_s1ap_id;
    s1ap_enb_path_switch_request_ack->ncc = (long) ue_nas_ctx->_as_security.ncc;
    memcpy ((uint8_t *) s1ap_enb_path_switch_request_ack->nh, ue_nas_ctx->_as_security.nh, AUTH_NH_SIZE);

    rc = itti_send_msg_to_task (TASK_S1AP, INSTANCE_DEFAULT, message_p);
    unlock_ue_contexts(ue_context_p);
    OAILOG_FUNC_RETURN (LOG_MME_APP, rc);
  }
  else {
    // Send PATH_SWITCH_REQUEST_FAILURE message to S1AP layer
    itti_s1ap_enb_path_switch_request_failure_t *s1ap_enb_path_switch_request_failure;
    message_p = itti_alloc_new_message (TASK_S1AP, S1AP_ENB_PATH_SWITCH_REQUEST_FAILURE);
    AssertFatal (message_p , "itti_alloc_new_message Failed");
    s1ap_enb_path_switch_request_failure = &message_p->ittiMsg.s1ap_enb_path_switch_request_failure;
    s1ap_enb_path_switch_request_failure->assoc_id = ue_context_p->sctp_assoc_id_key;
    s1ap_enb_path_switch_request_failure->ue_id = ue_context_p->mme_ue_s1ap_id;
    s1ap_enb_path_switch_request_failure->enb_ue_s1ap_id = ue_context_p->enb_ue_s1ap_id;
    s1ap_enb_path_switch_request_failure->cause_type = S1ap_Cause_PR_misc;
    s1ap_enb_path_switch_request_failure->cause_value = S1ap_CauseMisc_unspecified;
    rc = itti_send_msg_to_task (TASK_S1AP, INSTANCE_DEFAULT, message_p);
    unlock_ue_contexts(ue_context_p);
    OAILOG_FUNC_RETURN (LOG_MME_APP, rc);
  }
  unlock_ue_contexts(ue_context_p);
  // ignore message
  OAILOG_FUNC_RETURN (LOG_MME_APP, rc);
}

