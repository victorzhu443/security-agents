import torch


def load_forecaster(path, device="cpu"):
    """Restore the forecast model from a downloaded checkpoint."""
    return torch.load(path, map_location=device, weights_only=True)
