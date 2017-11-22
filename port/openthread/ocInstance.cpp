#include "ocInstance.hpp"

#include <common/code_utils.hpp>
#include <common/instance.hpp>
#include <common/new.hpp>

extern "C" {
#include "oc_api.h"
#include "oc_assert.h"
}

static otDEFINE_ALIGNED_VAR(sOcInstanceRaw, sizeof(ocInstance), uint64_t);

extern "C" {
void
ocInstanceInit(const oc_handler_t *handler)
{
  ocInstance *instance = NULL;

  instance = new(&sOcInstanceRaw) ocInstance();

  oc_assert(instance);

  oc_assert(oc_main_init(handler) == 0);
}

void
ocInstanceSignal()
{
  ocInstance::GetInstance()->PollRequest();
}
}

ocInstance *ocInstance::sInstance = NULL;

ocInstance *
ocInstance::GetInstance()
{
  return sInstance;
}

ocInstance::ocInstance() :
    mPollRequest(ot::Instance::Get(), &ocInstance::HandlePollRequest, this),
    mPollTimer(ot::Instance::Get(), &ocInstance::HandlePollTimer, this)
{
  sInstance = this;

  mPollRequest.Post();
}

void
ocInstance::PollRequest()
{
  mPollRequest.Post();
}

void
ocInstance::HandlePollRequest(ot::Tasklet &tasklet)
{
  (void)tasklet;

  ocInstance::GetInstance()->onPollRequest();
}

void
ocInstance::HandlePollTimer(ot::Timer &timer)
{
  (void)timer;

  ocInstance::GetInstance()->onPollTimer();
}

void
ocInstance::onPollRequest()
{
  oc_clock_time_t time = oc_main_poll();

  OC_DBG("Poll %lu\n", time);

  if (time){
    mPollTimer.StartAt(time, 0);
  } else {
    mPollTimer.Stop();
  }
}

void
ocInstance::onPollTimer()
{
  onPollRequest();
}

