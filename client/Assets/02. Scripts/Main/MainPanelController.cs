using UnityEngine;
using UnityEngine.UI;

public class MainPanelController : MonoBehaviour
{
    public void OnClickSinglePlayButton()
    {
        GameManager.Instance.ChangeToGameScene(Constants.GameType.SinglePlay);
    }

    public void OnClickMultiPlayButton()
    {
        GameManager.Instance.ChangeToGameScene(Constants.GameType.MultiPlay);
    }

    public void OnClickDualPlayButton()
    {
        GameManager.Instance.ChangeToGameScene(Constants.GameType.DualPlay);
    }

    public void OnClickSettingsButton()
    {

    }
}
