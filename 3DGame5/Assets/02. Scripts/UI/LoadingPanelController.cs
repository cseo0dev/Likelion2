using System;
using UnityEngine;
using DG.Tweening;
using UnityEngine.UI;

[RequireComponent(typeof(CanvasGroup))]
public class LoadingPanelController : MonoBehaviour
{
    [SerializeField] private Image gaugeImage;

    private CanvasGroup _canvasGroup;

    private void Awake()
    {
        _canvasGroup = GetComponent<CanvasGroup>();
        _canvasGroup.alpha = 0f;
        SetProgress(0f);
    }

    public void SetProgress(float progress)
    {
        gaugeImage.fillAmount = progress;
    }

    public void Show(Action onComplete)
    {
        _canvasGroup.DOFade(1f, 0.2f).OnComplete(() => onComplete?.Invoke());
        SetProgress(0f);
    }

    public void Hide(Action onComplete)
    {
        SetProgress(1f);
        _canvasGroup.DOFade(0f, 0.2f).OnComplete(() => onComplete?.Invoke());
    }
}