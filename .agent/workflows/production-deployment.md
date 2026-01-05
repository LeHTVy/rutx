# SNODE Production Deployment Guide

## GPU Requirements

| Use Case | GPU | VRAM | Can Run |
|----------|-----|------|---------|
| Solo/Small | RTX 4090 | 24GB | 33B models |
| Team | A100 40GB | 40GB | 70B models |
| Enterprise | A100 80GB / H100 | 80GB | Any |

## Model VRAM Reference
- deepseek-r1:8b → ~8GB
- deepseek-r1:14b → ~12GB  
- deepseek-r1:32b → ~24GB

## Recommended Setup
```yaml
GPU: RTX 4090 (24GB)
CPU: 8+ cores
RAM: 32GB
Storage: SSD 500GB
Model: deepseek-r1:14b-q4_K_M
```

## Future Optimizations (TODO)
- [ ] Async tool execution for parallel scans
- [ ] LLM response caching
- [ ] Batch processing for multi-target
- [ ] Model quantization (Q4_K_M)

## Cloud Options
| Provider | GPU | Cost/hr |
|----------|-----|---------|
| RunPod | A100 40GB | ~$1.50 |
| AWS g5.xlarge | A10G | ~$1.00 |
| Lambda Labs | A100 80GB | ~$1.99 |
