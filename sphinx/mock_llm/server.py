"""Mock LLM endpoint that simulates an OpenAI-compatible API for local development."""

import json
import time
import uuid

from fastapi import FastAPI, Request
from starlette.responses import StreamingResponse, JSONResponse

app = FastAPI(title="Mock LLM Provider")


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    body = await request.json()
    model = body.get("model", "mock-model")
    messages = body.get("messages", [])
    stream = body.get("stream", False)

    user_msg = messages[-1]["content"] if messages else "Hello"
    reply = f"Mock response to: {user_msg}"
    completion_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"
    timestamp = int(time.time())

    if stream:
        async def stream_response():
            # First chunk
            chunk = {
                "id": completion_id,
                "object": "chat.completion.chunk",
                "created": timestamp,
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "delta": {"role": "assistant", "content": reply},
                        "finish_reason": None,
                    }
                ],
            }
            yield f"data: {json.dumps(chunk)}\n\n"

            # Final chunk
            final = {
                "id": completion_id,
                "object": "chat.completion.chunk",
                "created": timestamp,
                "model": model,
                "choices": [
                    {"index": 0, "delta": {}, "finish_reason": "stop"}
                ],
            }
            yield f"data: {json.dumps(final)}\n\n"
            yield "data: [DONE]\n\n"

        return StreamingResponse(
            stream_response(), media_type="text/event-stream"
        )

    return JSONResponse(
        {
            "id": completion_id,
            "object": "chat.completion",
            "created": timestamp,
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": reply},
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": len(user_msg.split()),
                "completion_tokens": len(reply.split()),
                "total_tokens": len(user_msg.split()) + len(reply.split()),
            },
        }
    )


@app.get("/v1/models")
async def list_models():
    return {
        "object": "list",
        "data": [
            {"id": "mock-model", "object": "model", "owned_by": "sphinx-mock"},
            {"id": "mock-gpt-4", "object": "model", "owned_by": "sphinx-mock"},
        ],
    }
