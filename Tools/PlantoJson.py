'''
json plan输出工具，根据外部 Agent 提供的 json 信息或对话信息，来 Update Plan
'''

from agentscope.agent import ReActConfig
from agentscope.tool import ToolResponse
import json

phase_allow_agent={"recon", "analysis", "exploitation", "post_exploitation"}
status_allow_input={'完成','未进行','失败'}

def AddPlan(
        id:int,
        content:str,
        phase:phase_allow_agent,
        status:status_allow_input,
        evidencestr,
        origin:str
)->ToolResponse:


