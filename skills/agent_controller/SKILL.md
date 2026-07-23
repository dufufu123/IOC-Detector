# Agent Controller Skill

## 功能描述
AI Agent 对话模式入口。接收用户自然语言输入，理解意图，
自动选择合适的 Skill 完成 IOC 分析，支持多轮追问。

## 输入
- `user_input`: 用户输入的文本
- `skill_mgr`: SkillManager 实例
- `conversation_history`: 对话历史（可选）

## 输出
- `type`: answer | refuse
- `content`: 回复内容
- `history`: 更新后的对话历史

## 依赖
- openai (DeepSeek API)
- 所有现有 Skill
