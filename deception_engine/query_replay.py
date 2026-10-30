"""One Redis replay authority for ordinary and principal query lifecycles."""
import asyncio
from contextvars import ContextVar
from functools import wraps
import inspect
import logging
import time
from fastapi import HTTPException
from query_correlation import metadata
from query_idempotency import get_store, request_digest, owner_token

log=logging.getLogger(__name__)
owned=ContextVar("owned_query_request",default=None)
WAIT_SECONDS=0.25
POLL_SECONDS=0.05


def replay(scope, body_name, guard=None):
    def decorate(fn):
        signature=inspect.signature(inspect.unwrap(fn),eval_str=True)
        @wraps(fn)
        async def wrapped(*args,**kwargs):
            arguments=signature.bind_partial(*args,**kwargs).arguments
            body=arguments.get(body_name,{})
            try:correlation=metadata(body)
            except (ValueError,TypeError,AttributeError):
                raise HTTPException(400,"Invalid query correlation")
            if not correlation:return await fn(*args,**kwargs)
            identity=correlation["query_execution_id"]
            # The principal OWNER encompasses restore, producer, promotion and save.
            if scope=="decide" and owned.get()==("principal-query",identity):
                return await fn(*args,**kwargs)
            reference=guard(arguments) if guard is not None else None
            try:digest=request_digest(scope,body,reference)
            except (ValueError,TypeError):raise HTTPException(400,"Invalid idempotency request")
            token=owner_token()
            store=get_store()
            deadline=time.monotonic()+WAIT_SECONDS
            while True:
                try:status,result=await asyncio.to_thread(store.claim,identity,digest,token)
                except Exception:
                    log.warning("query idempotency store unavailable or invalid")
                    raise HTTPException(503,"Query request unavailable") from None
                if status=="COMPLETE":
                    if isinstance(result,HTTPException):raise result
                    return result
                if status=="CONFLICT":raise HTTPException(409,"IDEMPOTENCY_CONFLICT")
                if status=="OWNER":break
                if status!="CLAIMED" or time.monotonic()>=deadline:
                    raise HTTPException(503,"Query request not replayable" if status in {"AMBIGUOUS","COMPLETE_UNREPLAYABLE"} else "Query request unavailable")
                await asyncio.sleep(POLL_SECONDS)
            context=owned.set((scope,identity))
            try:
                result=await fn(*args,**kwargs)
            except HTTPException as exc:
                try:await asyncio.to_thread(store.finish,identity,digest,token,exc)
                except Exception:log.warning("query idempotency completion unavailable")
                raise
            except BaseException:
                try:await asyncio.to_thread(store.finish,identity,digest,token,ambiguous=True)
                except BaseException:log.warning("query idempotency outcome ambiguous")
                raise
            finally:
                owned.reset(context)
            try:await asyncio.to_thread(store.finish,identity,digest,token,result)
            except Exception:
                # Preserve the produced SQL result; retained claim suppresses retry
                # even if completion acknowledgement or storage was lost.
                log.warning("query idempotency completion unavailable")
            return result
        wrapped.__signature__=signature
        return wrapped
    return decorate
