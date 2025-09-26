using TMPro;
using UnityEngine;

public struct SignupData
{
    public string nickname;
    public string username;
    public string password;
}

public class SignupPanelController : PanelController
{
    [SerializeField] private TMP_InputField nicknameInputField;
    [SerializeField] private TMP_InputField usernameInputField;
    [SerializeField] private TMP_InputField passwordInputField;
    [SerializeField] private TMP_InputField confirmPasswordInputField;

    public void OnClickConfirmButton()
    {
        string nickname = nicknameInputField.text;
        string username = usernameInputField.text;
        string password = passwordInputField.text;
        string confirmPassword = confirmPasswordInputField.text;

        if (string.IsNullOrEmpty(nickname) || string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password) || string.IsNullOrEmpty(confirmPassword))
        {
            // TODO : ������ ���� �Է��ϵ��� ��û
            Shake();
            return;
        }

        // Confim Password Ȯ��
        if (password.Equals(confirmPassword))
        {
            var signupData = new SignupData();
            signupData.nickname = nickname;
            signupData.username = username;
            signupData.password = password;

            StartCoroutine(NetworkManager.Instance.Signup(signupData,
            () => // �α��� �������� ��
            {
                GameManager.Instance.OpenConfirmPanel("ȸ�����Կ� �����߽��ϴ�.", () =>
                {
                    Hide();
                });
            },
            (result) => // �α��� �������� ��
            {
                if (result == 0)
                {
                    GameManager.Instance.OpenConfirmPanel("�̹� �����ϴ� ������Դϴ�.", () =>
                    {
                        nicknameInputField.text = "";
                        usernameInputField.text = "";
                        passwordInputField.text = "";
                        confirmPasswordInputField.text = "";
                    });
                }
            }));
        }
    }

    public void OnClickCancelButton()
    {
        Hide();
    }
}
