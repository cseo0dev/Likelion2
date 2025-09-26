using TMPro;
using UnityEngine;

public struct SigninData
{
    public string username;
    public string password;
}

public struct SigninResult
{
    public int result; // Json Ÿ���� Ű ���� �̸� �����ؾ���
}

public class SigninPanelController : PanelController
{
    [SerializeField] private TMP_InputField usernameInputField;
    [SerializeField] private TMP_InputField passwordInputField;

    public void OnClickConfirmButton()
    {
        string username = usernameInputField.text;
        string password = passwordInputField.text;

        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
        {
            // TODO : ������ ���� �Է��ϵ��� ��û
            Shake();
            return;
        }

        var signinData = new SigninData();
        signinData.username = username;
        signinData.password = password;

        StartCoroutine(NetworkManager.Instance.Signin(signinData,
            () => // �α��� �������� ��
            {
                Hide();
            },
            (result) => // �α��� �������� ��
            {
                if (result == 0)
                {
                    GameManager.Instance.OpenConfirmPanel("���� �̸��� ��ȿ���� �ʽ��ϴ�.", () =>
                    {
                        usernameInputField.text = "";
                        passwordInputField.text = "";
                    });
                }
                else if (result == 1)
                {
                    GameManager.Instance.OpenConfirmPanel("�н����尡 ��ȿ���� �ʽ��ϴ�.", () =>
                    {
                        usernameInputField.text = "";
                        passwordInputField.text = "";
                    });
                }
            }));
    }

    public void OnClickJoinButton()
    {
        GameManager.Instance.OpenSignupPanel();
    }
}
