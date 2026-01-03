import json
from channels.generic.websocket import AsyncWebsocketConsumer
from core.chat_service import prepare_chat_context, handle_ai_chat
class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.slug = self.scope['url_route']['kwargs']['slug']
        self.session_id = self.scope['url_route']['kwargs']['session_id']
        await self.accept()

    async def receive(self, text_data):
        data = json.loads(text_data)
        user_message = data.get("message", "")

        try:

            from asgiref.sync import sync_to_async
            note, wallet, chat_history, note_content, session_id, total_tokens = \
                await sync_to_async(prepare_chat_context)(
                    self.scope["user"], self.slug, self.session_id, user_message
                )

            # run generator in thread
            result = await sync_to_async(list)(handle_ai_chat(
                note, self.scope["user"], session_id, user_message,
                note_content, wallet, chat_history
            ))
            for payload in result:
                await self.send(json.dumps(payload))

        except Exception as e:
            await self.send(json.dumps({"error": str(e)}))