# Lambda container image for the Dropbox-ingest connector -- compute-tier
# comparison (Cloud-Performance-Test-Matrix, 2026-07-26). Same demo/ + lambdas/
# code as Dockerfile.migrate (Fargate/EC2); only the entrypoint differs (a
# Lambda handler instead of fargate_entrypoint.py's script-that-runs-to-completion).
FROM public.ecr.aws/lambda/python:3.12

RUN pip install --no-cache-dir "boto3>=1.34" "requests>=2.31" "cryptography>=42.0"

# Flattened into LAMBDA_TASK_ROOT (Lambda requires the handler module to live
# there); lambdas/ goes to a sibling path outside it purely so dropbox_connector's
# own relative "../lambdas/pipeline" insert (CWD defaults to LAMBDA_TASK_ROOT in
# Lambda) resolves to the same place as the explicit absolute insert in
# lambda_handler.py -- belt and suspenders, not load-bearing either way.
COPY demo/ ${LAMBDA_TASK_ROOT}/
COPY lambdas/ /var/lambdas/
COPY scripts/lambda_ingest/lambda_handler.py ${LAMBDA_TASK_ROOT}/lambda_handler.py

CMD ["lambda_handler.handler"]
