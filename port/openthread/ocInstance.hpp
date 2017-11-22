#ifndef OCINSTANCE_HPP_
#define OCINSTANCE_HPP_

#include <common/tasklet.hpp>
#include <common/timer.hpp>

class ocInstance
{
public:
  ocInstance();

  static ocInstance *GetInstance();

  void PollRequest();

private:
  ot::Tasklet mPollRequest;
  ot::TimerMilli mPollTimer;
  static ocInstance *sInstance;

  static void HandlePollRequest(ot::Tasklet &aTasklet);
  static void HandlePollTimer(ot::Timer &aTimer);

  void onPollRequest();
  void onPollTimer();
};

#endif
