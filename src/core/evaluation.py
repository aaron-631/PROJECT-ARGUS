"""
Multi-stage Evaluation Pipeline.
Stage 1: Deterministic (regex, signatures, keywords)
Stage 2: Heuristic scoring
Stage 3: Optional semantic judge (JudgeBackend)
Stage 4: Risk matrix calculation
"""


class EvaluationPipeline:
    def __init__(self, judge_backend):
        self.judge = judge_backend

    async def evaluate(self, raw_output: str, context: dict) -> dict:
        # TODO: Week 5-6
        raise NotImplementedError
