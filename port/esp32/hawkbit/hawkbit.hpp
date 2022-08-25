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

// origin src: https://github.com/ctron/eclipse-hawkbit-arduino-ota-client

#pragma once

#include <vector>
#include <utility>
#include <string>
#include <map>
#include <list>


#include <cstdarg>
#include <cstdio>
#include <cstdbool>
#include "cJSON.h"
#include "esp_http_client.h"
#include "port/oc_log.h"

#define HTTP_CODE_OK 200
#define MAX_HTTP_OUTPUT_BUFFER 2048

class Print {
public:
  void printf(const char *fmt, ...)
  {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
  }
  void println() { printf("\n"); }
};

class Artifact;
class Chunk;
class Deployment;
class State;
class UpdateResult;
class DownloadResult;
class HawkbitClient;

class UpdateResult {
public:
  UpdateResult(uint32_t code)
    : _code(code)
  {
  }

  uint32_t code() const { return this->_code; }

private:
  uint32_t _code;
};

class DownloadResult {
public:
  DownloadResult(uint32_t code)
    : _code(code)
  {
  }

  uint32_t code() const { return this->_code; }

private:
  uint32_t _code;
};

class Artifact {
public:
  Artifact(const std::string &filename, uint32_t size,
           const std::map<std::string, std::string> &hashes,
           const std::map<std::string, std::string> &links)
    : _filename(filename)
    , _size(size)
    , _hashes(hashes)
    , _links(links)
  {
  }

  const std::string &filename() const { return _filename; }
  uint32_t size() const { return _size; }
  const std::map<std::string, std::string> &hashes() const { return _hashes; }
  const std::map<std::string, std::string> &links() const { return _links; }

  void dump(Print &out, const std::string &prefix = "") const
  {
    out.printf("%s%s %u\n", prefix.c_str(), this->_filename.c_str(),
               this->_size);
    out.printf("%sHashes\n", prefix.c_str());
    for (std::pair<std::string, std::string> element : this->_hashes) {
      out.printf("%s    %s = %s\n", prefix.c_str(), element.first.c_str(),
                 element.second.c_str());
    }
    out.printf("%sLinks\n", prefix.c_str());
    for (std::pair<std::string, std::string> element : this->_links) {
      out.printf("%s    %s = %s\n", prefix.c_str(), element.first.c_str(),
                 element.second.c_str());
    }
  }

private:
  std::string _filename;
  uint32_t _size;
  std::map<std::string, std::string> _hashes;
  std::map<std::string, std::string> _links;
};

class Chunk {
public:
  Chunk(const std::string &part, const std::string &version, const std::string &name,
        const std::list<Artifact> &artifacts)
    : _part(part)
    , _version(version)
    , _name(name)
    , _artifacts(artifacts)
  {
  }

  const std::string &part() const { return _part; }
  const std::string &version() const { return _version; }
  const std::string &name() const { return _name; }
  const std::list<Artifact> &artifacts() const { return _artifacts; }

  void dump(Print &out, const std::string &prefix = "") const
  {
    out.printf("%s%s - %s (%s)\n", prefix.c_str(), this->_name.c_str(),
               this->_version.c_str(), this->_part.c_str());
    for (Artifact a : this->_artifacts) {
      a.dump(out, prefix + "    ");
    }
  }

private:
  std::string _part;
  std::string _version;
  std::string _name;
  std::list<Artifact> _artifacts;
};

class Deployment {
public:
  Deployment() {}

  Deployment(const std::string &id, const std::string &download, const std::string &update,
             const std::list<Chunk> &chunks)
    : _id(id)
    , _download(download)
    , _update(update)
    , _chunks(chunks)
  {
  }

  const std::string &id() const { return _id; }
  const std::list<Chunk> &chunks() const { return _chunks; }

  void dump(Print &out, const std::string &prefix = "") const
  {
    out.printf("%sDeployment: %s\n", prefix.c_str(), this->_id.c_str());
    out.printf("%s    Download: %s, Update: %s\n", prefix.c_str(),
               this->_download.c_str(), this->_update.c_str());
    out.printf("%s    Chunks:\n", prefix.c_str());
    std::string chunkPrefix = prefix + "        ";
    for (Chunk c : this->_chunks) {
      c.dump(out, chunkPrefix);
    }
    out.println();
  };

private:
  std::string _id;
  std::string _download;
  std::string _update;
  std::list<Chunk> _chunks;
};

class Stop {
public:
  Stop() {}

  Stop(const std::string &id)
    : _id(id)
  {
  }

  const std::string &id() const { return this->_id; }

  void dump(Print &out, const std::string &prefix = "") const
  {
    out.printf("%sStop: %s\n", prefix.c_str(), this->_id.c_str());
  }

private:
  std::string _id;
};

class Registration {
public:
  Registration() {}

  Registration(const std::string &url)
    : _url(url)
  {
  }

  const std::string &url() const { return this->_url; }

  void dump(Print &out, const std::string &prefix = "") const
  {
    out.printf("%sRegistration: %s\n", prefix.c_str(), this->_url.c_str());
  }

private:
  std::string _url;
};

class State {

public:
  typedef enum { NONE, REGISTER, UPDATE, CANCEL } Type;

  State()
    : _type(State::NONE)
  {
  }

  State(const Stop &stop)
    : _type(State::CANCEL)
    , _stop(stop)
  {
  }

  State(const Registration &registration)
    : _type(State::REGISTER)
    , _registration(registration)
  {
  }

  State(const Deployment &deployment)
    : _type(State::UPDATE)
    , _deployment(deployment)
  {
  }

  bool is(Type type) const { return this->_type == type; }

  Type type() const { return this->_type; }
  const Deployment &deployment() const { return this->_deployment; }
  const Stop &stop() const { return this->_stop; }
  const Registration &registration() const { return this->_registration; }

  void dump(Print &out, const std::string &prefix = "") const
  {
    switch (this->_type) {
    case State::NONE:
      out.printf("%sState <NONE>\n", prefix.c_str());
      break;
    case State::UPDATE:
      out.printf("%sState <UPDATE>\n", prefix.c_str());
      this->_deployment.dump(out, "    ");
      break;
    case State::CANCEL:
      out.printf("%sState <CANCEL>\n", prefix.c_str());
      this->_stop.dump(out, "    ");
      break;
    case State::REGISTER:
      out.printf("%sState <REGISTER>\n", prefix.c_str());
      this->_registration.dump(out, "    ");
      break;
    default:
      out.printf("%sState <UNKNOWN>\n", prefix.c_str());
      break;
    }
  }

private:
  Type _type;
  Deployment _deployment;
  Stop _stop;
  Registration _registration;
};

class DownloadError {
public:
  DownloadError(uint32_t code)
    : _code(code)
  {
  }

  uint32_t code() const { return this->_code; }

private:
  uint32_t _code;
};

class Download {
public:
  esp_http_client_handle_t client() { return this->_client; }

private:
  esp_http_client_handle_t _client;

  Download(esp_http_client_handle_t client)
    : _client(client)
  {
  }

  friend HawkbitClient;
};

class HawkbitClient {
public:
  typedef enum { MERGE, REPLACE, REMOVE } MergeMode;

  HawkbitClient(const std::string &baseUrl, const std::string &tenantName,
                const std::string &controllerId, const std::string &securityToken, const std::string &caCert);

  State readState();

  void updateOTA(const Artifact &artifact) {
    updateOTA(artifact, "download-http");
  }
  void updateOTA(const Artifact &artifact, const std::string &linkType);

  template<typename DownloadHandler>
  void download(const Artifact &artifact, DownloadHandler function)
  {
    download(artifact, "download", function);
  }

  template<typename DownloadHandler>
  void download(const Artifact &artifact, const std::string &linkType,
                DownloadHandler function)
  {
    auto href = artifact.links().find(linkType);

    if (href == artifact.links().end()) {
      throw std::string("Missing link for download");
    }

    esp_http_client_handle_t client = GET(href->second, "");
    if (client == nullptr) {
      throw std::string("Failed to download artifact from " + href->second);
    }

    int code = esp_http_client_get_status_code(client);
    OC_DBG("Result - code: %d", code);

    if (code == HTTP_CODE_OK) {
      try {
        Download d(client);
        function(d);
      } catch (...) {
        esp_http_client_cleanup(client);
        throw;
      }
    }
    esp_http_client_cleanup(client);
    if (code != HTTP_CODE_OK) {
      throw DownloadError(code);
    }
  };

  UpdateResult reportProgress(const Deployment &deployment, uint32_t done,
                              uint32_t total, std::vector<std::string> details = {});

  UpdateResult reportComplete(const Deployment &deployment, bool success = true,
                              std::vector<std::string> details = {});

  UpdateResult reportScheduled(const Deployment &deployment,
                               std::vector<std::string> details = {});

  UpdateResult reportResumed(const Deployment &deployment,
                             std::vector<std::string> details = {});

  UpdateResult reportCancelAccepted(const Stop &stop,
                                    std::vector<std::string> details = {});

  UpdateResult reportCancelRejected(const Stop &stop,
                                    std::vector<std::string> details = {});

  UpdateResult reportCanceled(const Deployment &deployment,
                              std::vector<std::string> details = {});

  UpdateResult updateRegistration(const Registration &registration,
                                  const std::map<std::string, std::string> &data,
                                  MergeMode mergeMode = REPLACE,
                                  std::initializer_list<std::string> details = {});

  /**
   * Set the timeout (in ms) for the TCP connection.
   * @param timeout int timeout in ms
   */
  void timeout(int timeout) { _timeoutMs = timeout; }

private:
  // JsonDocument& _doc;
  // WiFiClient& _wifi;

  // HTTPClient _http;

  std::string _baseUrl;
  std::string _tenantName;
  std::string _controllerId;
  std::string _authToken;
  int _timeoutMs;
  std::string _caCert;

  Deployment readDeployment(const std::string &href);
  Stop readCancel(const std::string &href);

  std::string feedbackUrl(const Deployment &deployment) const;
  std::string feedbackUrl(const Stop &stop) const;

  template<typename IdProvider>
  UpdateResult sendFeedback(IdProvider id, const std::string &execution,
                            const std::string &finished,
                            std::vector<std::string> details);

  esp_http_client_handle_t POST(const std::string &url, const char *body);
  esp_http_client_handle_t GET(const std::string &url, const std::string &accept);

  esp_http_client_config_t getClientConfig(const std::string &url) { 
    esp_http_client_config_t config = {};
    config.url = url.c_str();
    config.timeout_ms = _timeoutMs;
    config.cert_pem = _caCert.c_str();
    config.cert_len= _caCert.length();
    return config;
  }

  static std::string updateOTAToken;
  static esp_err_t updateOTACbk(esp_http_client_handle_t client);
};