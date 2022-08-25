/*******************************************************************************
 * Copyright (c) 2020 Red Hat Inc
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/

#include "hawkbit.hpp"
#include "esp_https_ota.h"
#include "esp_system.h"

HawkbitClient::HawkbitClient(const std::string &baseUrl,
                             const std::string &tenantName,
                             const std::string &controllerId,
                             const std::string &securityToken,
                             const std::string &caCert)
  : _baseUrl(baseUrl)
  , _tenantName(tenantName)
  , _controllerId(controllerId)
  , _authToken("TargetToken " + securityToken)
  , _caCert(caCert)
{
}

UpdateResult
HawkbitClient::updateRegistration(const Registration &registration,
                                  const std::map<std::string, std::string> &data,
                                  MergeMode mergeMode,
                                  std::initializer_list<std::string> details)
{
  cJSON *root = cJSON_CreateObject();
  std::string mode = "";
  switch (mergeMode) {
  case MERGE:
    mode = "merge";
    break;
  case REPLACE:
    mode = "replace";
    break;
  case REMOVE:
    mode = "remove";
    break;
  }
  cJSON_AddItemToObject(root, "mode", cJSON_CreateString(mode.c_str()));
  cJSON *jdata = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "data", jdata);
  for (const std::pair<std::string, std::string> entry : data) {
    cJSON_AddItemToObject(jdata, std::string(entry.first).c_str(),
                          cJSON_CreateString(entry.second.c_str()));
  }
  cJSON *status = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "status", status);
  cJSON *status_details = cJSON_CreateArray();
  cJSON_AddItemToObject(status, "details", status_details);
  for (auto detail : details) {
    cJSON_AddItemToArray(status_details, cJSON_CreateString(detail.c_str()));
  }
  cJSON_AddItemToObject(status, "execution", cJSON_CreateString("closed"));
  cJSON *status_result = cJSON_CreateObject();
  cJSON_AddItemToObject(status, "result", status_result);
  cJSON_AddItemToObject(status, "finished", cJSON_CreateString("success"));

  esp_http_client_config_t config = getClientConfig(registration.url());
  esp_http_client_handle_t client = esp_http_client_init(&config);
  if (client == NULL) {
    cJSON_Delete(root);
    OC_DBG("Failed to set init http client");
    return UpdateResult(-1);
  }
  esp_err_t err = esp_http_client_set_method(client, HTTP_METHOD_PUT);
  if (err != ESP_OK) {
    cJSON_Delete(root);
    esp_http_client_cleanup(client);
    OC_DBG("Failed to set HTTP method: %s", esp_err_to_name(err));
    return UpdateResult(-1);
  }

  err = esp_http_client_set_header(client, "Authorization", _authToken.c_str());
  if (err != ESP_OK) {
    cJSON_Delete(root);
    esp_http_client_cleanup(client);
    OC_DBG("Failed to set header \"Authorization\": %s", esp_err_to_name(err));
    return UpdateResult(-1);
  }
  err = esp_http_client_set_header(client, "Content-Type", "application/json");
  if (err != ESP_OK) {
    cJSON_Delete(root);
    esp_http_client_cleanup(client);
    OC_DBG("Failed to set header \"Content-Type\": %s", esp_err_to_name(err));
    return UpdateResult(-1);
  }
  err = esp_http_client_set_header(client, "Accept", "application/hal+json");
  if (err != ESP_OK) {
    cJSON_Delete(root);
    esp_http_client_cleanup(client);
    OC_DBG("Failed to set header \"Accept\": %s", esp_err_to_name(err));
    return UpdateResult(-1);
  }

  char *rendered = cJSON_PrintUnformatted(root);
  cJSON_Delete(root);
  size_t len = strlen(rendered);
  (void)len; // ignore unused
  err = esp_http_client_set_post_field(client, rendered, strlen(rendered));
  if (err != ESP_OK) {
    free(rendered);
    esp_http_client_cleanup(client);
    OC_DBG("Failed to set POST field: %s", esp_err_to_name(err));
    return UpdateResult(-1);
  }
  OC_DBG("JSON - len: %d", len);
  err = esp_http_client_perform(client);
  free(rendered);
  if (err != ESP_OK) {
    esp_http_client_cleanup(client);
    OC_DBG("Failed to http perform: %s", esp_err_to_name(err));
    return UpdateResult(-1);
  }
  int code = esp_http_client_get_status_code(client);
  OC_DBG("Result - code: %d", code);

  char output_buffer[MAX_HTTP_OUTPUT_BUFFER];
  int data_read = esp_http_client_read_response(client, output_buffer,
                                                MAX_HTTP_OUTPUT_BUFFER - 1);
  if (data_read > 0) {
    output_buffer[data_read] = 0;
    OC_DBG("Result - payload %s", output_buffer);
  }
  esp_http_client_cleanup(client);

  return UpdateResult(code);
}

static const cJSON *
getObjectItemAtPath(const cJSON *node, std::list<std::string> path)
{
  const cJSON *o = node;
  for (auto key : path) {
    o = cJSON_GetObjectItem(o, key.c_str());
    if (o == nullptr) {
      return nullptr;
    }
  }
  return o;
}

static std::string
getStringItemAtPath(const cJSON *node, std::list<std::string> path)
{
  const cJSON *o = getObjectItemAtPath(node, path);
  if (o != nullptr && cJSON_GetStringValue(o) != nullptr) {
    return cJSON_GetStringValue(o);
  }
  return "";
}

static const cJSON *
getArrayItemAtPath(const cJSON *node, std::list<std::string> path)
{
  const cJSON *o = getObjectItemAtPath(node, path);
  if (o != nullptr && cJSON_IsArray(o)) {
    return o;
  }
  return nullptr;
}

template<typename T>
T
getNumberItemAtPath(const cJSON *node, std::list<std::string> path,
                    T default_value)
{
  const cJSON *o = getObjectItemAtPath(node, path);
  if (o != nullptr && cJSON_IsNumber(o)) {
    return (T)cJSON_GetNumberValue(o);
  }
  return default_value;
}

esp_http_client_handle_t
HawkbitClient::GET(const std::string &url, const std::string &accept)
{
  esp_http_client_config_t config = getClientConfig(url);
  esp_http_client_handle_t client = esp_http_client_init(&config);
  if (client == NULL) {
    OC_DBG("Failed to set init http client");
    return nullptr;
  }
  esp_err_t err = esp_http_client_set_method(client, HTTP_METHOD_GET);
  if (err != ESP_OK) {
    esp_http_client_cleanup(client);
    OC_DBG("Failed to set HTTP method: %s", esp_err_to_name(err));
    return nullptr;
  }
  err = esp_http_client_set_header(client, "Authorization", _authToken.c_str());
  if (err != ESP_OK) {
    esp_http_client_cleanup(client);
    OC_DBG("Failed to set header \"Authorization\": %s", esp_err_to_name(err));
    return nullptr;
  }
  if (accept != "") {
    err = esp_http_client_set_header(client, "Accept", accept.c_str());
    if (err != ESP_OK) {
      esp_http_client_cleanup(client);
      OC_DBG("Failed to set header \"Accept\": %s", esp_err_to_name(err));
      return nullptr;
    }
  }

  err = esp_http_client_perform(client);
  if (err != ESP_OK) {
    esp_http_client_cleanup(client);
    OC_DBG("Failed to set header \"Accept\": %s", esp_err_to_name(err));
    return nullptr;
  }
  return client;
}

esp_http_client_handle_t
HawkbitClient::POST(const std::string &url, const char *body)
{
  esp_http_client_config_t config = getClientConfig(url);
  esp_http_client_handle_t client = esp_http_client_init(&config);
  if (client == NULL) {
    OC_DBG("Failed to set init http client");
    return nullptr;
  }
  esp_err_t err = esp_http_client_set_method(client, HTTP_METHOD_POST);
  if (err != ESP_OK) {
    esp_http_client_cleanup(client);
    OC_DBG("Failed to set HTTP method: %s", esp_err_to_name(err));
    return nullptr;
  }
  err = esp_http_client_set_header(client, "Authorization", _authToken.c_str());
  if (err != ESP_OK) {
    esp_http_client_cleanup(client);
    OC_DBG("Failed to set header \"Authorization\": %s", esp_err_to_name(err));
    return nullptr;
  }
  err = esp_http_client_set_header(client, "Accept", "application/hal+json");
  if (err != ESP_OK) {
    esp_http_client_cleanup(client);
    OC_DBG("Failed to set header \"Accept\": %s", esp_err_to_name(err));
    return nullptr;
  }
  err = esp_http_client_set_header(client, "Content-Type", "application/json");
  if (err != ESP_OK) {
    esp_http_client_cleanup(client);
    OC_DBG("Failed to set header \"Accept\": %s", esp_err_to_name(err));
    return nullptr;
  }

  err = esp_http_client_set_post_field(client, body, strlen(body));
  if (err != ESP_OK) {
    esp_http_client_cleanup(client);
    OC_DBG("Failed to set post field: %s", esp_err_to_name(err));
    return nullptr;
  }

  err = esp_http_client_perform(client);
  if (err != ESP_OK) {
    esp_http_client_cleanup(client);
    OC_DBG("Failed to client perform: %s", esp_err_to_name(err));
    return nullptr;
  }
  return client;
}

State
HawkbitClient::readState()
{
  std::string url = this->_baseUrl + "/" + this->_tenantName +
                    "/controller/v1/" + this->_controllerId;
  esp_http_client_handle_t client = this->GET(url, "application/hal+json");
  if (client == NULL) {
    OC_DBG("Failed to get http client");
    throw 1;
  }
  int code = esp_http_client_get_status_code(client);
  OC_DBG("Result - code: %d", code);
  char output_buffer[MAX_HTTP_OUTPUT_BUFFER];
  int data_read = esp_http_client_read_response(client, output_buffer,
                                                MAX_HTTP_OUTPUT_BUFFER - 1);
  if (data_read > 0) {
    output_buffer[data_read] = 0;
    OC_DBG("Result - payload %s", output_buffer);
  }
  esp_http_client_cleanup(client);
  cJSON *root = nullptr;
  if (code == HTTP_CODE_OK) {
    root = cJSON_Parse(output_buffer);
    if (root == nullptr) {
      // FIXME: need a way to handle errors
      throw 1;
    }
  }
  std::string href =
    getStringItemAtPath(root, { "_links", "deploymentBase", "href" });
  if (href != "") {
    OC_DBG("Fetching deployment: %s", href.c_str());
    cJSON_Delete(root);
    return State(this->readDeployment(href));
  }

  href = getStringItemAtPath(root, { "_links", "configData", "href" });
  if (href != "") {
    OC_DBG("Need to register", href.c_str());
    cJSON_Delete(root);
    return State(Registration(href));
  }

  href = getStringItemAtPath(root, { "_links", "cancelAction", "href" });
  if (href != "") {
    OC_DBG("Fetching cancel action: %s", href.c_str());
    cJSON_Delete(root);
    return State(this->readCancel(href));
  }

  cJSON_Delete(root);
  OC_DBG("No update");
  return State();
}

std::map<std::string, std::string>
toMap(const cJSON *obj)
{
  std::map<std::string, std::string> result;
  if (obj == nullptr) {
    return result;
  }
  cJSON *node = nullptr;
  cJSON_ArrayForEach(node, obj)
  {
    if (cJSON_IsString(node)) {
      result[node->string] = std::string(cJSON_GetStringValue(node));
    }
  }
  return result;
}

std::map<std::string, std::string>
toLinks(const cJSON *obj)
{
  std::map<std::string, std::string> result;
  if (obj == nullptr) {
    return result;
  }
  cJSON *node = nullptr;
  cJSON_ArrayForEach(node, obj)
  {
    result[node->string] = std::string(getStringItemAtPath(node, { "href" }));
  }
  return result;
}

std::list<Artifact>
artifacts(const cJSON *artifacts)
{
  std::list<Artifact> result;
  if (artifacts == nullptr) {
    return result;
  }

  cJSON *artifact_node = nullptr;
  cJSON_ArrayForEach(artifact_node, artifacts)
  {
    Artifact artifact(
      getStringItemAtPath(artifact_node, { "filename" }),
      getNumberItemAtPath(artifact_node, { "size" }, 0),
      toMap(getObjectItemAtPath(artifact_node, { "hashes" })),
      toLinks(getObjectItemAtPath(artifact_node, { "_links" })));
    result.push_back(artifact);
  }

  return result;
}

std::list<Chunk>
chunks(const cJSON *chunks)
{
  std::list<Chunk> result;
  if (chunks == nullptr) {
    return result;
  }
  cJSON *chunk_node = nullptr;
  cJSON_ArrayForEach(chunk_node, chunks)
  {
    Chunk chunk(getStringItemAtPath(chunk_node, { "part" }),
                getStringItemAtPath(chunk_node, { "version" }),
                getStringItemAtPath(chunk_node, { "name" }),
                artifacts(getArrayItemAtPath(chunk_node, { "artifacts" })));
    result.push_back(chunk);
  };

  return result;
}

Deployment
HawkbitClient::readDeployment(const std::string &url)
{
  esp_http_client_handle_t client = this->GET(url, "application/hal+json");
  if (client == NULL) {
    OC_DBG("Failed to get http client");
    throw 1;
  }
  int code = esp_http_client_get_status_code(client);
  OC_DBG("Result - code: %d", code);
  char output_buffer[MAX_HTTP_OUTPUT_BUFFER];
  int data_read = esp_http_client_read_response(client, output_buffer,
                                                MAX_HTTP_OUTPUT_BUFFER - 1);
  if (data_read > 0) {
    output_buffer[data_read] = 0;
    OC_DBG("Result - payload %s", output_buffer);
  }
  esp_http_client_cleanup(client);
  cJSON *root = nullptr;
  if (code == HTTP_CODE_OK) {
    root = cJSON_Parse(output_buffer);
    if (root == nullptr) {
      // FIXME: need a way to handle errors
      throw 1;
    }
  }
  std::string id = getStringItemAtPath(root, { "id" });
  std::string download =
    getStringItemAtPath(root, { "deployment", "download" });
  std::string update = getStringItemAtPath(root, { "deployment", "update" });
  Deployment deployment =
    Deployment(id, download, update,
               chunks(getArrayItemAtPath(root, { "deployment", "chunks" })));
  cJSON_Delete(root);
  return deployment;
}

Stop
HawkbitClient::readCancel(const std::string &url)
{
  esp_http_client_handle_t client = this->GET(url, "application/hal+json");
  if (client == NULL) {
    OC_DBG("Failed to get http client");
    throw 1;
  }
  int code = esp_http_client_get_status_code(client);
  OC_DBG("Result - code: %d", code);
  char output_buffer[MAX_HTTP_OUTPUT_BUFFER];
  int data_read = esp_http_client_read_response(client, output_buffer,
                                                MAX_HTTP_OUTPUT_BUFFER - 1);
  if (data_read > 0) {
    output_buffer[data_read] = 0;
    OC_DBG("Result - payload %s", output_buffer);
  }
  esp_http_client_cleanup(client);
  cJSON *root = nullptr;
  if (code == HTTP_CODE_OK) {
    root = cJSON_Parse(output_buffer);
    if (root == nullptr) {
      // FIXME: need a way to handle errors
      throw 1;
    }
  }

  Stop stop = Stop(getStringItemAtPath(root, { "cancelAction", "stopId" }));
  cJSON_Delete(root);
  return stop;
}

std::string
HawkbitClient::feedbackUrl(const Deployment &deployment) const
{
  return this->_baseUrl + "/" + this->_tenantName + "/controller/v1/" +
         this->_controllerId + "/deploymentBase/" + deployment.id() +
         "/feedback";
}

std::string
HawkbitClient::feedbackUrl(const Stop &stop) const
{
  return this->_baseUrl + "/" + this->_tenantName + "/controller/v1/" +
         this->_controllerId + "/cancelAction/" + stop.id() + "/feedback";
}

template<typename IdProvider>
UpdateResult
HawkbitClient::sendFeedback(IdProvider id, const std::string &execution,
                            const std::string &finished, std::vector<std::string> details)
{
  cJSON *root = cJSON_CreateObject();
  if (root == nullptr) {
    throw 1;
  }
  cJSON_AddItemToObject(root, "id", cJSON_CreateString(id.id().c_str()));
  cJSON *status = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "status", status);
  cJSON *status_details = cJSON_CreateArray();
  cJSON_AddItemToObject(status, "details", status_details);
  for (auto detail : details) {
    cJSON_AddItemToArray(status_details, cJSON_CreateString(detail.c_str()));
  }
  cJSON_AddItemToObject(status, "execution",
                        cJSON_CreateString(execution.c_str()));
  cJSON *status_result = cJSON_CreateObject();
  cJSON_AddItemToObject(status, "result", status_result);
  cJSON_AddItemToObject(status, "finished",
                        cJSON_CreateString(finished.c_str()));

  char *rendered = cJSON_PrintUnformatted(root);
  cJSON_Delete(root);
  if (rendered == nullptr) {
    throw 1;
  }
  esp_http_client_handle_t client = this->POST(this->feedbackUrl(id), rendered);
  free(rendered);
  if (client == nullptr) {
    throw 1;
  }
  int code = esp_http_client_get_status_code(client);
  OC_DBG("Result - code: %d", code);

  char output_buffer[MAX_HTTP_OUTPUT_BUFFER];
  int data_read = esp_http_client_read_response(client, output_buffer,
                                                MAX_HTTP_OUTPUT_BUFFER - 1);
  if (data_read > 0) {
    output_buffer[data_read] = 0;
    OC_DBG("Result - payload %s", output_buffer);
  }
  esp_http_client_cleanup(client);
  return UpdateResult(code);
}

UpdateResult
HawkbitClient::reportProgress(const Deployment &deployment, uint32_t done,
                              uint32_t total, std::vector<std::string> details)
{
  return sendFeedback(deployment, "proceeding", "none", details);
}

UpdateResult
HawkbitClient::reportScheduled(const Deployment &deployment,
                               std::vector<std::string> details)
{
  return sendFeedback(deployment, "scheduled", "none", details);
}

UpdateResult
HawkbitClient::reportResumed(const Deployment &deployment,
                             std::vector<std::string> details)
{
  return sendFeedback(deployment, "resumed", "none", details);
}

UpdateResult
HawkbitClient::reportComplete(const Deployment &deployment, bool success,
                              std::vector<std::string> details)
{
  return sendFeedback(deployment, "closed", success ? "success" : "failure",
                      details);
}

UpdateResult
HawkbitClient::reportCanceled(const Deployment &deployment,
                              std::vector<std::string> details)
{
  return sendFeedback(deployment, "canceled", "none", details);
}

UpdateResult
HawkbitClient::reportCancelAccepted(const Stop &stop,
                                    std::vector<std::string> details)
{
  return sendFeedback(stop, "closed", "success", details);
}

UpdateResult
HawkbitClient::reportCancelRejected(const Stop &stop,
                                    std::vector<std::string> details)
{
  return sendFeedback(stop, "closed", "failure", details);
}

esp_err_t
HawkbitClient::updateOTACbk(esp_http_client_handle_t client)
{
  esp_http_client_set_header(client, "Authorization",
                             HawkbitClient::updateOTAToken.c_str());
  return ESP_OK;
}

void
HawkbitClient::updateOTA(const Artifact &artifact, const std::string &linkType)
{
  auto href = artifact.links().find(linkType);

  if (href == artifact.links().end()) {
    throw std::string("Missing link for download");
  }

  esp_https_ota_config_t ota_config = {};
  esp_http_client_config_t http_config = this->getClientConfig(href->second);
  ota_config.http_config = &http_config;
  ota_config.partial_http_download = false;
  updateOTAToken = _authToken;
  ota_config.http_client_init_cb = HawkbitClient::updateOTACbk;
  esp_err_t err = esp_https_ota(&ota_config);
  if (err != ESP_OK) {
    std::string err_str = esp_err_to_name(err);
    throw std::string("esp_https_ota failed: " + err_str);
  }
}