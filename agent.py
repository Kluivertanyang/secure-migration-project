# # agent.py
# from langchain_openai import ChatOpenAI
# from langchain_core.prompts import PromptTemplate
# from aws_checks import *
# import json
# from dotenv import load_dotenv
# load_dotenv()
# import os
# from langchain_core.messages import HumanMessage
# import re  # for improved bucket detection

# OPENAI_KEY = os.getenv("OPENAI_API_KEY")

# # -------------------------------
# # LLM Helper
# # -------------------------------
# def llm_summarize_raw(text: str):
#     """
#     Summarizes AWS findings via LLM.
#     """
#     llm = ChatOpenAI(
#         model="gpt-4o-mini",
#         temperature=0.3,
#         openai_api_key=os.getenv("OPENAI_API_KEY")
#     )
#     messages = [HumanMessage(content=text)]
#     response = llm.generate([messages])
#     return response.generations[0][0].text

# # -------------------------------
# # Chat Agent
# # -------------------------------
# def chat_with_agent(user_message: str):
#     user_lower = user_message.lower()
#     service = intent = bucket_name = None

#     # --- Detect Service & Intent ---
#     if "s3" in user_lower:
#         service = "s3"
#         if "list" in user_lower:
#             intent = "list"
#         elif "status" in user_lower or "compliance" in user_lower:
#             intent = "status"
#         elif "details" in user_lower or "info" in user_lower:
#             intent = "detailed"
#         else:
#             intent = "status"

#     # --- S3 Handling ---
#     if service == "s3":
#         if intent == "list":
#             buckets = list_s3_buckets()
#             return {"Buckets": buckets, "Total": len(buckets)}

#         elif intent == "status":
#             buckets = list_s3_buckets()
#             aws_data = [call_aws_action("s3", "status", None, b) for b in buckets]
#             summary_prompt = f"""
#             You are a cloud security assistant. Here is the AWS data retrieved:
#             {json.dumps(aws_data, indent=2)}
#             Summarize the findings in a concise, user-friendly way with key insights and recommended actions.
#             """
#             return llm_summarize_raw(summary_prompt)

#         elif intent == "detailed":
#             # --- Improved Bucket Detection ---
#             # Convert spaces to dashes and match typical S3 bucket naming
#             bucket_match = re.search(r"([a-z0-9.-]{3,63})", user_message.replace(" ", "-"))
#             bucket_name = bucket_match.group(1) if bucket_match else None

#             if bucket_name:
#                 aws_data = call_aws_action("s3", "status", None, bucket_name)
#                 detailed_info = {
#                     "Bucket": bucket_name,
#                     "Versioning": aws_data["meta"].get("versioning"),
#                     "MFA_Delete": aws_data["meta"].get("delete_protection", "N/A"),
#                     "SSE": aws_data["meta"].get("encryption_rules"),
#                     "KMS_Integrated": aws_data["meta"].get("kms_key_id") is not None,
#                     "Resource_Policy": "Exists" if aws_data["meta"].get("bucket_policy") else "None",
#                     "Public_Access_Block": aws_data["meta"].get("public_access_block", True),
#                     "Issues": aws_data["issues"] if aws_data["issues"] else "None",
#                     "Tags": aws_data["meta"].get("tags", {})
#                 }
#                 return detailed_info

#     # --- Fallback for other queries ---
#     summary_prompt = f"""
#     You are an AWS cloud assistant. Answer the following user query conversationally:
#     {user_message}
#     """
#     return llm_summarize_raw(summary_prompt)


# agent.py
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage
import os, json, re
from dotenv import load_dotenv
from aws_checks import call_aws_action, list_s3_buckets

load_dotenv()

# -------------------------------
# LLM Helper
# -------------------------------
def llm_chat(prompt: str):
    """Simple wrapper to call OpenAI for natural responses."""
    llm = ChatOpenAI(
        model="gpt-4o-mini",
        temperature=0.3,
        openai_api_key=os.getenv("OPENAI_API_KEY")
    )
    messages = [HumanMessage(content=prompt)]
    response = llm.generate([messages])
    return response.generations[0][0].text


# -------------------------------
# Chat Agent Logic
# -------------------------------
def chat_with_agent(user_message: str):
    user_lower = user_message.lower()
    service = intent = None

    # Detect S3 context
    if "s3" in user_lower or "bucket" in user_lower:
        service = "s3"
        if "list" in user_lower:
            intent = "list"
        elif "status" in user_lower or "compliance" in user_lower:
            intent = "status"
        elif "detail" in user_lower or "info" in user_lower:
            intent = "detailed"
        else:
            intent = "status"

    # -------------------------------
    # Handle S3 logic
    # -------------------------------
    if service == "s3":
        if intent == "list":
            buckets = list_s3_buckets()
            return {"Buckets": buckets, "Total": len(buckets)}

        elif intent == "status":
            buckets = list_s3_buckets()
            aws_data = [call_aws_action("s3", "status", None, b) for b in buckets]
            summary_prompt = f"""
            You are a helpful cloud security assistant.
            Here are the AWS S3 bucket findings:
            {json.dumps(aws_data, indent=2)}
            Summarize this in a user-friendly way with key insights and best practice recommendations.
            """
            return llm_chat(summary_prompt)

        elif intent == "detailed":
            # Extract bucket name heuristically
            bucket_match = re.search(r"([a-z0-9.-]{3,63})", user_message.replace(" ", "-"))
            bucket_name = bucket_match.group(1) if bucket_match else None

            if not bucket_name:
                return {"error": "Could not detect bucket name in message."}

            aws_data = call_aws_action("s3", "status", None, bucket_name)
            return {
                "Bucket": bucket_name,
                "Versioning": aws_data["meta"].get("versioning"),
                "SSE": aws_data["meta"].get("encryption_rules"),
                "PublicAccessBlock": aws_data["meta"].get("public_access_block"),
                "Issues": aws_data["issues"],
            }

    # -------------------------------
    # Fallback for general questions
    # ---------------------
