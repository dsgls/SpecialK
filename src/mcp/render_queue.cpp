/**
 * This file is part of Special K.
 *
 * Special K is free software : you can redistribute it
 * and/or modify it under the terms of the GNU General Public License
 * as published by The Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Special K is distributed in the hope that it will be useful,
 *
 * But WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Special K.
 *
 *   If not, see <http://www.gnu.org/licenses/>.
 *
**/

#include <SpecialK/stdafx.h>

#include "tools.h"

#include <deque>
#include <exception>
#include <memory>
#include <mutex>

using json = nlohmann::json;

#define SK_MCP_LOG_SRC L" MCP-Srv "

// SK_MCP_RenderJob::state
static constexpr LONG SK_MCP_JobPending   = 0;
static constexpr LONG SK_MCP_JobRunning   = 1;
static constexpr LONG SK_MCP_JobAbandoned = 2;

struct SK_MCP_RenderJob {
  std::function <json (void)> fn;
  json                        result;
  std::exception_ptr          error;
  HANDLE                      done  = nullptr;
  volatile LONG               state = SK_MCP_JobPending;

  explicit SK_MCP_RenderJob (std::function <json (void)>&& job) : fn (std::move (job))
  {
    done =
      CreateEvent (nullptr, TRUE, FALSE, nullptr);
  }

  ~SK_MCP_RenderJob (void)
  {
    if (done != nullptr)
      CloseHandle (done);
  }

  SK_MCP_RenderJob            (const SK_MCP_RenderJob&) = delete;
  SK_MCP_RenderJob& operator= (const SK_MCP_RenderJob&) = delete;
};

// Jobs run in the order they were queued, whichever worker thread queued them.
static SK_Thread_HybridSpinlock                         _mcp_render_lock;
static std::deque <std::shared_ptr <SK_MCP_RenderJob>>  _mcp_render_jobs;
static volatile LONG                                    _mcp_render_jobs_pending = 0;


json
SK_MCP_RunOnRenderThread ( std::function <json (void)> fn,
                           DWORD                       timeout_ms )
{
  auto job =
    std::make_shared <SK_MCP_RenderJob> (std::move (fn));

  if (job->done == nullptr)
    throw SK_MCP_ToolError { "could not create the job completion event" };

  {
    std::scoped_lock lock (_mcp_render_lock);

    _mcp_render_jobs.push_back (job);
  }

  InterlockedIncrement (&_mcp_render_jobs_pending);

  const HANDLE stop =
    SK_MCP_StopEvent ();

  const HANDLE wait_on [2] = { job->done, stop };

  const DWORD wait =
    WaitForMultipleObjects ( (stop != nullptr) ? 2 : 1, wait_on,
                               FALSE, timeout_ms );

  if (wait != WAIT_OBJECT_0)
  {
    // WAIT_FAILED cannot be told apart from a stuck presenting thread, so it
    //   takes the timeout path as well.
    if ( SK_MCP_JobPending ==
           InterlockedCompareExchange ( &job->state, SK_MCP_JobAbandoned,
                                                     SK_MCP_JobPending ) )
    {
      // The drain never claimed it, so it never ran and never will; the queue
      //   drops it and decrements the counter the next time it presents.
      if (wait == WAIT_OBJECT_0 + 1)
        throw SK_MCP_ToolError { "server stopping" };

      char szError [160] = { };

      snprintf ( szError, sizeof (szError),
                   "presenting thread did not run the job within %lu ms; "
                   "is the game presenting frames?", timeout_ms );

      throw SK_MCP_ToolError { szError };
    }

    // The presenting thread owns the job now and will write into it, so the
    //   only safe thing left is to wait for it however long that takes.
    SK_LOG0 ( ( L"An MCP job overran its %lu ms timeout; waiting for the "
                L"presenting thread to finish it", timeout_ms ), SK_MCP_LOG_SRC );

    WaitForSingleObject (job->done, INFINITE);
  }

  if (job->error)
    std::rethrow_exception (job->error);

  return
    job->result;
}

// Retires one claimed job: drops it out of the pending count and wakes its
//   waiter, whether the job body returned, threw, or unwound past every
//   handler.
struct SK_MCP_JobCompletion {
  SK_MCP_RenderJob* job;

  explicit SK_MCP_JobCompletion (SK_MCP_RenderJob* claimed) noexcept : job (claimed) { }

  ~SK_MCP_JobCompletion (void) noexcept
  {
    InterlockedDecrement (&_mcp_render_jobs_pending);

    SetEvent (job->done);
  }

  SK_MCP_JobCompletion            (const SK_MCP_JobCompletion&) = delete;
  SK_MCP_JobCompletion& operator= (const SK_MCP_JobCompletion&) = delete;
};

void
SK_MCP_DrainRenderJobs (void)
{
  // The whole per-frame cost of the feature when it is off or idle.
  if (0 == ReadAcquire (&_mcp_render_jobs_pending))
    return;

  std::deque <std::shared_ptr <SK_MCP_RenderJob>> jobs;

  {
    std::scoped_lock lock (_mcp_render_lock);

    jobs.swap (_mcp_render_jobs);
  }

  for (auto& job : jobs)
  {
    if ( SK_MCP_JobPending !=
           InterlockedCompareExchange ( &job->state, SK_MCP_JobRunning,
                                                     SK_MCP_JobPending ) )
    {
      // Abandoned by a waiter that gave up; nobody is listening for it.
      InterlockedDecrement (&_mcp_render_jobs_pending);

      continue;
    }

    // Once the job is claimed the waiter is committed to WaitForSingleObject
    //   with no timeout, so the event has to be set on every path out of here.
    //   A destructor covers the ones no handler can: under /EHa a structured
    //   exception from a job body that forgot its own SEH frame (§5) unwinds
    //   through the typed catches below, and the waiter would hang for the
    //   life of the process.  It gets a default-constructed result instead.
    SK_MCP_JobCompletion completion (job.get ());

    // No catch (...): the project builds with /EHa and a catch-all would
    //   swallow access violations that belong to SK's crash handler.  A job
    //   that calls game code wraps that call in its own SEH frame.
    try
    {
      job->result = job->fn ();
    }

    catch (const SK_MCP_ToolError&)
    {
      job->error = std::current_exception ();
    }

    catch (const std::exception&)
    {
      job->error = std::current_exception ();
    }
  }
}
